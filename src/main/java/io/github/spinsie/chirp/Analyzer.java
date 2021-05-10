package io.github.spinsie.chirp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.sonarsource.sonarlint.core.StandaloneSonarLintEngineImpl;
import org.sonarsource.sonarlint.core.client.api.common.Language;
import org.sonarsource.sonarlint.core.client.api.common.LogOutput;
import org.sonarsource.sonarlint.core.client.api.common.LogOutput.Level;
import org.sonarsource.sonarlint.core.client.api.common.RuleKey;
import org.sonarsource.sonarlint.core.client.api.common.TextRange;
import org.sonarsource.sonarlint.core.client.api.common.analysis.AnalysisResults;
import org.sonarsource.sonarlint.core.client.api.common.analysis.ClientInputFile;
import org.sonarsource.sonarlint.core.client.api.common.analysis.Issue;
import org.sonarsource.sonarlint.core.client.api.standalone.StandaloneAnalysisConfiguration;
import org.sonarsource.sonarlint.core.client.api.standalone.StandaloneGlobalConfiguration;

/**
 * Provides code analysis 
 *
 * @see Analyzer#lint(Map)
 */
public final class Analyzer {

	private static final Map<Language, String> pluginURLs = new EnumMap<>(Language.class);

	static {
		pluginURLs.put(Language.JAVA, "https://repo1.maven.org/maven2/org/sonarsource/java/sonar-java-plugin/6.15.1.26025/sonar-java-plugin-6.15.1.26025.jar");
	}

	private static final class ScannerProperties {
		private Path baseDir;
		private List<Language> languages;
		private IssueSeverity severityLevel;
		private Set<String> issueIgnore;
		private Set<String> ruleExclude;
		private List<ClientInputFile> sources;
		private List<ClientInputFile> testSources;
		private Map<String, String> raw;
	}

	public enum IssueSeverity {
		BLOCKER, CRITICAL, MAJOR, MINOR, INFO;
	}

	public enum IssueType {
		BUG, VULNERABILITY, CODE_SMELL;
	}

	public static final class Finding {

		private IssueSeverity severity;
		private IssueType type;
		private String message;
		private String ref;
		private Issue issue;

		public IssueSeverity severity() {
			return severity;
		}

		public IssueType type() {
			return type;
		}

		public String message() {
			return message;
		}

		public String ref() {
			return ref;
		}

		public Issue issue() {
			return issue;
		}

	}

	public static final class Analysis {

		private List<Finding> findings;
		private List<String> unusedIgnores;
		private AnalysisResults results;
		private IssueSeverity severityLevel;
		private StandaloneSonarLintEngineImpl engine;

		public List<Finding> findings() {
			return findings;
		}

		public List<String> unusedIgnores() {
			return unusedIgnores;
		}

		public Collection<ClientInputFile> failedAnalysisFiles() {
			return results.failedAnalysisFiles();
		}

	}

	private static ScannerProperties setup(Map<String, ?> properties) throws IOException {
		final ScannerProperties sp = new ScannerProperties();
		sp.raw = properties.entrySet().stream().collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue().toString()));
		sp.baseDir = Paths.get(Optional.ofNullable(sp.raw.get("base.dir"))
				.orElse(System.getProperty("user.dir")));
		sp.languages = Arrays.stream(Objects.requireNonNull(sp.raw.get("lang"), "lang").split(","))
				.map(l -> Language.forKey(l.toLowerCase()).orElseThrow(() -> new InstantiationError(l + " is not a supported language")))
				.collect(Collectors.toList());
		sp.severityLevel = Optional.ofNullable(sp.raw.get("severity.level"))
				.map(s -> IssueSeverity.valueOf(s.toUpperCase()))
				.orElse(IssueSeverity.INFO);
		sp.issueIgnore = Optional.ofNullable(sp.raw.get("issue.ignore"))
				.map(s -> new HashSet<>(Arrays.asList(s.split(","))))
				.orElse(new HashSet<>());
		sp.ruleExclude = Optional.ofNullable(sp.raw.get("rule.exclude"))
				.map(s -> new HashSet<>(Arrays.asList(s.split(","))))
				.orElse(new HashSet<>());
		final Optional<String> issueIgnoreFile = Optional.ofNullable(sp.raw.get("issue.ignore.file"));
		if (issueIgnoreFile.isPresent()) {
			sp.issueIgnore.addAll(readFile(issueIgnoreFile.get()));
		}
		final Optional<String> ruleExcludeFile = Optional.ofNullable(sp.raw.get("rule.exclude.file"));
		if (ruleExcludeFile.isPresent()) {
			sp.ruleExclude.addAll(readFile(ruleExcludeFile.get()));
		};
		sp.sources = findSources(sp.baseDir, sp.raw.get("sonar.sources"), false);
		sp.testSources = findSources(sp.baseDir, sp.raw.get("sonar.tests"), true);
		return sp;
	}

	private static List<ClientInputFile> findSources(Path baseDir, String property, boolean test) throws IOException {
		final Optional<String> p = Optional.ofNullable(property);
		if (p.isPresent()) {
			for (String s : p.get().split(",")) {
				final Path path = Paths.get(s);
				if (Files.exists(path)) {
					try (Stream<Path> walk = Files.walk(path)) {
						return walk.filter(Files::isRegularFile)
							.distinct()
							.map(asClientInputFile(baseDir, test))
							.collect(Collectors.toList());
					}
				}
			}
		}
		return Collections.emptyList();
	}

	private static URL cachePlugin(Language lang) throws IOException {
		final String url = Objects.requireNonNull(pluginURLs.get(lang));
		final boolean windows = System.getProperty("os.name").contains("Windows");
		final Path cache;
		if (windows) {
			cache = Paths.get(System.getenv("LOCALAPPDATA")).resolve("temp/chirp");
		} else {
			cache = Paths.get("/tmp/chirp");
		}
		final File plugin = cache.resolve(lang.getLanguageKey() + ".jar").toFile();
		if (!plugin.exists()) {
			Files.createDirectories(cache);
			try (ReadableByteChannel rbs = Channels.newChannel(new URL(url).openStream());
					FileOutputStream fos = new FileOutputStream(plugin)) {
				fos.getChannel().transferFrom(rbs, 0, Long.MAX_VALUE);
			}
		}
		return plugin.toURI().toURL();
	}

	private static Finding finding(Issue i, String hash) throws IOException {
		final String ln = System.lineSeparator();
		final String ls = "| ";
		final StringBuilder sb = new StringBuilder();
		sb.append("+----- Finding ----->").append(ln);
		sb.append(ls).append("Type: ").append(i.getType()).append(ln);
		sb.append(ls).append("Severity: ").append(i.getSeverity()).append(ln);
		sb.append(ls).append("RuleKey: ").append(i.getRuleKey()).append(ln);
		sb.append(ls).append("Rule: ").append(i.getRuleName()).append(ln);
		sb.append(ls).append("Message: ").append(i.getMessage()).append(ln);
		sb.append(ls).append(ln);
		final ClientInputFile file = i.getInputFile();
		if (file != null) {
			sb.append(ls).append("File: ").append(file.relativePath());
			if (i.getTextRange() != null) {
				sb.append(":").append(i.getStartLine()).append(ln);
				final String[] lines = file.contents().split(ln);
				for (int j = i.getStartLine() - 1, k = i.getEndLine(); j < k; ++j) {
					sb.append(ls).append("> ").append(lines[j].trim()).append(ln);
				}
			} else {
				sb.append(ln);
			}
			sb.append(ls).append(ln);
		}
		sb.append(ls).append("Reference: ").append(hash).append(ln);
		sb.append("+------------------->").append(ln);
		final Finding finding = new Finding();
		finding.type = IssueType.valueOf(i.getType());
		finding.severity = IssueSeverity.valueOf(i.getSeverity());
		finding.message = sb.toString();
		finding.issue = i;
		finding.ref = hash;
		return finding;
	}

	private static LogOutput logger() {
		return (formattedMessage, level) -> {
			if (level.ordinal() <= Level.WARN.ordinal() && !"No workDir in SonarLint".equals(formattedMessage) ) {
				System.err.println(String.format("%s [%s] %s", Instant.now(), level.toString(), formattedMessage));
			}
		};
	}

	private static String summary(List<Finding> findings) {
		final String ln = System.lineSeparator();
		final String ls = "| ";
		final StringBuilder sb = new StringBuilder();
		final Map<IssueType, List<Finding>> groups = findings.stream().collect(Collectors.groupingBy(f -> f.type));
		sb.append("+---------- Summary ----------+").append(ln);
		sb.append(ls).append(String.format("Bugs %22s |", groups.getOrDefault(IssueType.BUG, Collections.emptyList()).size())).append(ln);
		sb.append(ls).append(String.format("Vulerabilities %12s |", groups.getOrDefault(IssueType.VULNERABILITY, Collections.emptyList()).size())).append(ln);
		sb.append(ls).append(String.format("Code Smells %15s |", groups.getOrDefault(IssueType.CODE_SMELL, Collections.emptyList()).size())).append(ln);
		sb.append("+-----------------------------+").append(ln);
		return sb.toString();
	}

	private static String configuration(StandaloneSonarLintEngineImpl config, IssueSeverity severityLevel) {
		final String ln = System.lineSeparator();
		final String ls = "| ";
		final StringBuilder sb = new StringBuilder();
		sb.append("+----- Sonarlint Analysis ----->").append(ln);
		sb.append(ls).append("Active Rules: ").append(config.getGlobalContainer().getActiveRuleKeys().stream().map(k -> config.getRuleDetails(k)).filter(d -> IssueSeverity.valueOf(d.get().getSeverity()).ordinal() <= severityLevel.ordinal()).count()).append(ln);
		sb.append(ls).append("Plugins: ").append(config.getGlobalContainer().getPluginDetails().stream().map(info -> info.name()).collect(Collectors.toList())).append(ln);
		sb.append("+------------------------------>").append(ln);
		return sb.toString();
	}

	private static String json(List<Finding> findings) {
		final StringBuilder sb = new StringBuilder();
		final String ln = System.lineSeparator();
		final Map<IssueType, List<Finding>> groups = findings.stream().collect(Collectors.groupingBy(f -> f.type));
		final IntFunction<StringBuilder> tab = n -> {
			for (int i = 0; i < n; ++i) {
				sb.append('\t');
			}
			return sb;
		};
		sb.append("{").append(ln);
		tab.apply(1).append("\"summary\": {").append(ln);
		tab.apply(2).append("\"bugs\": ").append(groups.getOrDefault(IssueType.BUG, Collections.emptyList()).size()).append(",").append(ln);
		tab.apply(2).append("\"vulerabilities\": ").append( groups.getOrDefault(IssueType.VULNERABILITY, Collections.emptyList()).size()).append(",").append(ln);
		tab.apply(2).append("\"code_smells\": ").append( groups.getOrDefault(IssueType.CODE_SMELL, Collections.emptyList()).size()).append(ln);
		tab.apply(1).append("}").append(',').append(ln);
		tab.apply(1).append("\"findings\": ").append("[").append(ln);
		for (int i = 0, length = findings.size(), last = length - 1; i < length; ++i) {
			final Finding f = findings.get(i);
			tab.apply(2).append("{").append(ln);
			tab.apply(3).append("\"severity\": ").append('"').append(f.severity.toString()).append('"').append(',').append(ln);
			tab.apply(3).append("\"type\": ").append('"').append(f.type.toString()).append('"').append(',').append(ln);
			tab.apply(3).append("\"rule_key\": ").append('"').append(f.issue.getRuleKey()).append('"').append(',').append(ln);
			tab.apply(3).append("\"rule_name\": ").append('"').append(f.issue.getRuleName().replace("\\", "\\\\").replace("\"", "\\\"")).append('"').append(',').append(ln);
			final String message = f.issue.getMessage();
			if (message != null) {
				tab.apply(3).append("\"message\": ").append('"').append(message.replace("\\", "\\\\").replace("\"", "\\\"")).append('"').append(',').append(ln);
			}
			final ClientInputFile file = f.issue.getInputFile();
			if (file != null) {
				tab.apply(3).append("\"location\": {").append(ln);
				tab.apply(4).append("\"file\": ").append('"').append(file.relativePath().replace("\\", "/")).append('"');
				if (f.issue.getTextRange() != null) {
					sb.append(',').append(ln);
					tab.apply(4).append("\"start_line\": ").append(f.issue.getStartLine()).append(',').append(ln);
					tab.apply(4).append("\"start_line_offset\": ").append(f.issue.getStartLineOffset()).append(',').append(ln);
					tab.apply(4).append("\"end_line\": ").append(f.issue.getEndLine()).append(',').append(ln);
					tab.apply(4).append("\"end_line_offset\": ").append(f.issue.getEndLineOffset()).append(ln);
				} else {
					sb.append(ln);
				}
				tab.apply(3).append("},").append(ln);
			}
			tab.apply(3).append("\"ref\": ").append('"').append(f.ref).append('"').append(ln);
			tab.apply(2).append("}");
			if (i != last) {
				sb.append(",");
			}
			sb.append(ln);
		}
		tab.apply(1).append("]").append(ln);
		sb.append("}").append(ln);
		return sb.toString();
	}

	private static Function<Path, ClientInputFile> asClientInputFile(Path base, boolean test) {
		return p -> new ClientInputFile() {
			@Override
			@Deprecated
			public String getPath() {
				return p.toAbsolutePath().toString();
			}
			@Override
			public boolean isTest() {
				return test;
			}
			@Override
			public Charset getCharset() {
				return StandardCharsets.UTF_8;
			}
			@Override
			public <G> G getClientObject() {
				return null;
			}
			@Override
			public InputStream inputStream() throws IOException {
				return Files.newInputStream(p);
			}
			@Override
			public String contents() throws IOException {
				return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
			}
			@Override
			public String relativePath() {
				return base.toAbsolutePath().relativize(p.toAbsolutePath()).toString();
			}
			@Override
			public URI uri() {
				return p.toUri();
			}
		};
	}

	private static String hash(Issue issue) throws NoSuchAlgorithmException, IOException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		final List<String> properties = new LinkedList<>();
		final ClientInputFile file = issue.getInputFile();
		final TextRange textRange = issue.getTextRange();
		final String message = issue.getMessage();
		properties.add(issue.getRuleKey());
		if (message != null) {
			properties.add(issue.getMessage());
		}
		if (file != null) {
			properties.add(file.relativePath());
			if (textRange != null) {
				final String[] lines = file.contents().split(System.lineSeparator());
				for (int j = issue.getStartLine() - 1, k = issue.getEndLine(); j < k; ++j) {
					properties.add(lines[j].trim());
				}
			}
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(md.digest(String.join(";", properties).getBytes()));
	}

	private static List<String> readFile(String filePath) throws IOException {
		try (Stream<String> lines = Files.lines(Paths.get(filePath))) {
			return lines.map(String::trim)
				.filter(l -> !l.isEmpty())
				.filter(l -> !l.startsWith("//"))
				.map(l -> l.replaceFirst("\\S+//.*$", ""))
				.collect(Collectors.toList());
		}
	}

	private static Map<String, String> parse(String[] args) {
		final Map<String, String> map = new HashMap<>();
		final Iterator<String> it = Arrays.asList(args).iterator();
		while (it.hasNext()) {
			final String arg = it.next();
			if (arg.startsWith("--")) {
				final String word = arg.substring(2);
				if ("verbose".equals(word)) {
					map.put(word, null);
				} else if (it.hasNext()) {
					map.put(word.replace('-', '.'), it.next());
				}
			}
		}
		return map;
	}

	public static void main(String[] args) throws IOException {
		final Map<String, String> props = parse(args);
		final Optional<Path> outputPath = Optional.ofNullable(props.get("output.file"))
				.map(Paths::get);
		final boolean verbose = props.containsKey("verbose");
		final Analysis analysis = lint(props);
		System.out.println(configuration(analysis.engine, analysis.severityLevel));
		for (ClientInputFile f : analysis.results.failedAnalysisFiles()) {
			System.err.println(Instant.now() + " [ERROR] Failed to analyze " + f.relativePath());
		}
		if (!analysis.unusedIgnores.isEmpty()) {
			System.err.println(Instant.now() + " [WARN] Unused issue ignores: " + analysis.unusedIgnores + System.lineSeparator());
		}
		if (outputPath.isPresent()) {
			final File file = outputPath.get().toFile();
			Optional.ofNullable(file.getParentFile()).ifPresent(File::mkdirs);
			file.createNewFile();
			try (FileOutputStream fos = new FileOutputStream(file)) {
				fos.write(json(analysis.findings).getBytes());
				fos.flush();
			}
		}
		if ((verbose && outputPath.isPresent()) || !outputPath.isPresent()) {
			analysis.findings.forEach(i -> System.out.println(i.message));
		}
		System.out.println(summary(analysis.findings));
	}

	public static Analysis lint(Map<String, ?> properties) throws IOException {
		final ScannerProperties props = setup(properties);
		final StandaloneGlobalConfiguration.Builder scb = StandaloneGlobalConfiguration.builder()
			.setExtraProperties(props.raw);
		for (Language lang : props.languages) {
			scb.addEnabledLanguage(lang);
			scb.addPlugin(cachePlugin(lang));
		}
		final StandaloneAnalysisConfiguration.Builder sacb = StandaloneAnalysisConfiguration.builder()
			.setBaseDir(props.baseDir)
			.addInputFiles(props.sources)
			.addInputFiles(props.testSources)
			.addExcludedRules(props.ruleExclude.stream().map(RuleKey::parse).collect(Collectors.toList()));
		final List<String> ignored = new LinkedList<>();
		final List<Finding> findings = new ArrayList<>();
		final StandaloneSonarLintEngineImpl engine = new StandaloneSonarLintEngineImpl(scb.build());
		final AnalysisResults results = engine.analyze(sacb.build(), i -> {
			if (IssueSeverity.valueOf(i.getSeverity()).ordinal() > props.severityLevel.ordinal()) {
				return;
			}
			try {
				final String hash = hash(i);
				if (!props.issueIgnore.contains(hash)) {
					findings.add(finding(i, hash));
				} else {
					ignored.add(hash);
				}
			} catch (NoSuchAlgorithmException | IOException e1) {
				e1.printStackTrace();
			}
		}, logger(), null);
		Collections.sort(findings, (lhs, rhs) -> Integer.compare(lhs.severity.ordinal(), rhs.severity.ordinal()));
		final List<String> unusedIgnores = new LinkedList<>(props.issueIgnore);
		unusedIgnores.removeAll(ignored);
		final Analysis analysis = new Analysis();
		analysis.results = results;
		analysis.findings = findings;
		analysis.unusedIgnores = unusedIgnores;
		analysis.engine = engine;
		analysis.severityLevel = props.severityLevel;
		return analysis;
	}

}