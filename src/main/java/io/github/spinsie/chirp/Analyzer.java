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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import org.sonarsource.sonarlint.core.StandaloneSonarLintEngineImpl;
import org.sonarsource.sonarlint.core.client.api.common.Language;
import org.sonarsource.sonarlint.core.client.api.common.LogOutput;
import org.sonarsource.sonarlint.core.client.api.common.RuleKey;
import org.sonarsource.sonarlint.core.client.api.common.analysis.AnalysisResults;
import org.sonarsource.sonarlint.core.client.api.common.analysis.ClientInputFile;
import org.sonarsource.sonarlint.core.client.api.common.analysis.Issue;
import org.sonarsource.sonarlint.core.client.api.standalone.StandaloneAnalysisConfiguration;
import org.sonarsource.sonarlint.core.client.api.standalone.StandaloneGlobalConfiguration;

public final class Analyzer {

	private static final Map<Language, String> pluginURLs = new HashMap<Language, String>() {
		{
			this.put(Language.JAVA, "https://repo1.maven.org/maven2/org/sonarsource/java/sonar-java-plugin/6.15.1.26025/sonar-java-plugin-6.15.1.26025.jar");
		}
	};

	public enum IssueSeverity {
		BLOCKER, CRITICAL, MAJOR, MINOR, INFO;
	}

	public enum IssueType {
		BUG, VULNERABILITY, CODE_SMELL;
	}

	public static final class Finding {
		public IssueSeverity severity;
		public IssueType type;
		public String message;
		public String ref;
		public Issue issue;
	}

	public static final class Analysis {
		public List<Finding> findings;
		public List<String> unusedIgnores;
		public AnalysisResults results;
		private IssueSeverity severityLevel;
		private StandaloneSonarLintEngineImpl engine;
	}

	public static Analysis lint(Map<String, ?> properties) throws IOException {
		final Map<String, String> props = properties.entrySet().stream().collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue().toString()));
		final Path baseDir = Paths.get(Optional.ofNullable(props.get("base.dir"))
				.orElse(System.getProperty("user.dir")));
		final List<Language> languages = Arrays.stream(Objects.requireNonNull(props.get("lang"), "lang").split(","))
				.map(l -> Language.forKey(l.toLowerCase()).orElseThrow(() -> new InstantiationError(l + " is not a supported language")))
				.collect(Collectors.toList());
		final IssueSeverity severityLevel = Optional.ofNullable(props.get("severity.level"))
				.map(s -> IssueSeverity.valueOf(s.toUpperCase()))
				.orElse(IssueSeverity.INFO);
		final Set<String> issueIgnore = Optional.ofNullable(props.get("issue.ignore"))
				.map(s -> new HashSet<>(Arrays.asList(s.split(","))))
				.orElse(new HashSet<>());
		final Set<String> ruleExclude = Optional.ofNullable(props.get("rule.exclude"))
				.map(s -> new HashSet<>(Arrays.asList(s.split(","))))
				.orElse(new HashSet<>());
		final Optional<String> issueIgnoreFile = Optional.ofNullable(props.get("issue.ignore.file"));
		if (issueIgnoreFile.isPresent()) {
			issueIgnore.addAll(readFile(issueIgnoreFile.get()));
		}
		final Optional<String> ruleExcludeFile = Optional.ofNullable(props.get("rule.exclude.file"));
		if (ruleExcludeFile.isPresent()) {
			ruleExclude.addAll(readFile(ruleExcludeFile.get()));
		}
		final StandaloneGlobalConfiguration.Builder scb = StandaloneGlobalConfiguration.builder().setExtraProperties(props);
		for (Language lang : languages) {
			scb.addEnabledLanguage(lang).addPlugin(cachePlugin(lang));
		}
		final StandaloneGlobalConfiguration sc = scb.build();
		final StandaloneAnalysisConfiguration.Builder sacb = StandaloneAnalysisConfiguration.builder().setBaseDir(baseDir);
		final BiConsumer<String, Boolean> addFiles = (k, b) -> {
			final Optional<String> p = Optional.ofNullable(props.get(k));
			if (p.isPresent()) {
				for (String s : p.get().split(",")) {
					try {
						final Path path = Paths.get(s);
						if (Files.exists(path)) {
							sacb.addInputFiles(Files.walk(path)
								.filter(Files::isRegularFile)
								.distinct()
								.map(asClientInputFile(baseDir, b))
								.collect(Collectors.toList()));
						}
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}
		};
		addFiles.accept("sonar.sources", false);
		addFiles.accept("sonar.tests", true);
		ruleExclude.stream().map(RuleKey::parse).forEach(sacb::addExcludedRule);
		final StandaloneAnalysisConfiguration sac = sacb.build();
		final List<String> ignored = new LinkedList<>();
		final List<Finding> findings = new ArrayList<>();
		final StandaloneSonarLintEngineImpl engine = new StandaloneSonarLintEngineImpl(sc);
		final AnalysisResults results = engine.analyze(sac, i -> {
			if (IssueSeverity.valueOf(i.getSeverity()).ordinal() > severityLevel.ordinal()) {
				return;
			}
			try {
				final String hash = hash(i);
				if (!issueIgnore.contains(hash)) {
					findings.add(finding(i, hash));
				} else {
					ignored.add(hash);
				}
			} catch (NoSuchAlgorithmException | IOException e1) {
				e1.printStackTrace();
			}
		}, logger(), null);
		Collections.sort(findings, (lhs, rhs) -> Integer.compare(lhs.severity.ordinal(), rhs.severity.ordinal()));
		final List<String> unusedIgnores = new LinkedList<>(issueIgnore);
		unusedIgnores.removeAll(ignored);
		final Analysis analysis = new Analysis();
		analysis.results = results;
		analysis.findings = findings;
		analysis.unusedIgnores = unusedIgnores;
		analysis.engine = engine;
		analysis.severityLevel = severityLevel;
		return analysis;
	}

	private static URL cachePlugin(Language lang) throws IOException {
		final String url = Objects.requireNonNull(pluginURLs.get(lang));
		final boolean windows = System.getProperty("os.name").contains("Windows");
		final Path cache;
		if (windows) {
			cache = Paths.get(System.getenv("LOCALAPPDATA")).resolve("temp/sonarlint");
		} else {
			cache = Paths.get("/tmp/sonarlint");
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

	private static Finding finding(Issue i, String hash) throws NoSuchAlgorithmException, IOException {
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
		sb.append(ls).append("File: ").append(i.getInputFile().relativePath()).append(":").append(i.getStartLine()).append(ln);
		final String[] lines = i.getInputFile().contents().split(ln);
		for (int j = i.getStartLine() - 1, k = i.getEndLine(); j < k; ++j) {
			sb.append(ls).append("> ").append(lines[j].trim()).append(ln);
		}
		sb.append(ls).append(ln);
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
		return new LogOutput() {
			@Override
			public void log(String formattedMessage, Level level) {
				if (level.ordinal() <= Level.WARN.ordinal() && !"No workDir in SonarLint".equals(formattedMessage) ) {
					System.err.println(String.format("%s [%s] %s", Instant.now(), level.toString(), formattedMessage));
				}
			}
		};
	}

	private static String summary(List<Finding> findings) {
		final String ln = System.lineSeparator();
		final String ls = "| ";
		final StringBuilder sb = new StringBuilder();
		sb.append("+---------- Summary ----------+").append(ln);
		sb.append(ls).append(String.format("Bugs %22s |", findings.stream().filter(f -> f.type == IssueType.BUG).count())).append(ln);
		sb.append(ls).append(String.format("Vulerabilities %12s |", findings.stream().filter(f -> f.type == IssueType.VULNERABILITY).count())).append(ln);
		sb.append(ls).append(String.format("Code Smells %15s |", findings.stream().filter(f -> f.type == IssueType.CODE_SMELL).count())).append(ln);
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
		final IntFunction<StringBuilder> tab = n -> {
			for (int i = 0; i < n; ++i) {
				sb.append('\t');
			}
			return sb;
		};
		sb.append("{").append(ln);
		tab.apply(1).append("\"summary\": {").append(ln);
		tab.apply(2).append("\"bugs\": ").append(findings.stream().filter(f -> f.type == IssueType.BUG).count()).append(",").append(ln);
		tab.apply(2).append("\"vulerabilities\": ").append(findings.stream().filter(f -> f.type == IssueType.VULNERABILITY).count()).append(",").append(ln);
		tab.apply(2).append("\"code_smells\": ").append(findings.stream().filter(f -> f.type == IssueType.CODE_SMELL).count()).append(ln);
		tab.apply(1).append("}").append(',').append(ln);
		tab.apply(1).append("\"findings\": ").append("[").append(ln);
		for (int i = 0, length = findings.size(), last = length - 1; i < length; ++i) {
			final Finding f = findings.get(i);
			tab.apply(2).append("{").append(ln);
			tab.apply(3).append("\"severity\": ").append('"').append(f.severity.toString()).append('"').append(',').append(ln);
			tab.apply(3).append("\"type\": ").append('"').append(f.type.toString()).append('"').append(',').append(ln);
			tab.apply(3).append("\"rule_key\": ").append('"').append(f.issue.getRuleKey()).append('"').append(',').append(ln);
			tab.apply(3).append("\"rule_name\": ").append('"').append(f.issue.getRuleName().replace("\\", "\\\\").replace("\"", "\\\"")).append('"').append(',').append(ln);
			tab.apply(3).append("\"message\": ").append('"').append(f.issue.getMessage().replace("\\", "\\\\").replace("\"", "\\\"")).append('"').append(',').append(ln);
			tab.apply(3).append("\"location\": {").append(ln);
			tab.apply(4).append("\"file\": ").append('"').append(f.issue.getInputFile().relativePath().replace("\\", "/")).append('"').append(',').append(ln);
			tab.apply(4).append("\"start_line\": ").append(f.issue.getStartLine()).append(',').append(ln);
			tab.apply(4).append("\"start_line_offset\": ").append(f.issue.getStartLineOffset()).append(',').append(ln);
			tab.apply(4).append("\"end_line\": ").append(f.issue.getEndLine()).append(',').append(ln);
			tab.apply(4).append("\"end_line_offset\": ").append(f.issue.getEndLineOffset()).append(ln);
			tab.apply(3).append("},").append(ln);
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

	private static String hash(Issue issue) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		return Base64.getUrlEncoder().withoutPadding().encodeToString(md.digest(String.join(";",
				issue.getRuleKey(),
				issue.getInputFile().relativePath(),
				issue.getStartLine().toString(),
				issue.getEndLine().toString(),
				issue.getStartLineOffset().toString(),
				issue.getEndLineOffset().toString()).getBytes()));
	}

	private static List<String> readFile(String filePath) throws IOException {
		return Files.lines(Paths.get(filePath)).map(l -> l.trim()).collect(Collectors.toList());
	}

	private static Map<String, String> parse(String[] args) {
		final Map<String, String> map = new HashMap<>();
		final Iterator<String> it = Arrays.asList(args).iterator();
		while (it.hasNext()) {
			final String arg = it.next();
			if (arg.startsWith("--")) {
				final String word = arg.substring(2);
				if ("quiet".equals(word)) {
					map.put(word, null);
				} else if (it.hasNext()) {
					map.put(word, it.next().replace('-', '.'));
				}
			}
		}
		return map;
	}

	public static void main(String[] args) throws IOException {
		final Map<String, String> props = parse(args);
		final Optional<Path> outputPath = Optional.ofNullable(props.get("output.file"))
				.map(Paths::get);
		final boolean quiet = props.containsKey("quiet");
		final Analysis analysis = lint(props);
		System.out.println(configuration(analysis.engine, analysis.severityLevel));
		for (ClientInputFile f : analysis.results.failedAnalysisFiles()) {
			System.err.println(Instant.now() + " [ERROR] Failed toLowerCase analyze " + f.relativePath());
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
		if (!quiet) {
			analysis.findings.forEach(i -> System.out.println(i.message));
			System.out.println(summary(analysis.findings));
		}
	}

}