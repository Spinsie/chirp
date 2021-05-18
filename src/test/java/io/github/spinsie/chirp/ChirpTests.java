package io.github.spinsie.chirp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import io.github.spinsie.chirp.Chirp.Analysis;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChirpTests {

	private static final List<String> ruleKeys = Arrays.asList("java:S1220", "java:S106", "java:S100");

	@BeforeClass
	public static void setup() throws InterruptedException, IOException {
		Files.createDirectories(Paths.get("build/its/java"));
		final ProcessBuilder pb = new ProcessBuilder(Arrays.asList("javac", "-d", "build/its/java", "its/java/Test.java"));
		assertEquals("Compilation", 0, pb.start().waitFor());
	}

	@Test
	public void testJavaCli() throws IOException {
		final String command = "--lang java --sonar-sources its/java --sonar-java-binaries build/its/java --output-file build/its/java/findings.json";
		Chirp.main(command.split(" "));
		final File f = Paths.get("build/its/java/findings.json").toFile();
		assertJsonFindings(f);
		f.delete();
	}

	@Test
	public void testJavaApi() throws IOException {
		final Map<String, String> props = new HashMap<>();
		props.put("lang", "java");
		props.put("sonar.sources", "its/java");
		props.put("sonar.java.binaries", "build/its/java");
		final Analysis a = Chirp.scan(props);
		final File f = Paths.get("build/its/java/findings.json").toFile();
		a.export(f);
		assertJsonFindings(f);
		f.delete();
	}

	@Test
	public void testSeverityLevel() throws IOException {
		final Map<String, String> props = new HashMap<>();
		props.put("lang", "java");
		props.put("severity.level", "none");
		props.put("sonar.sources", "its/java");
		props.put("sonar.java.binaries", "build/its/java");
		final Analysis a = Chirp.scan(props);
		assertEquals(0, a.findings().size());
	}

	@Test
	public void testSeverityLevelOverride() throws IOException {
		final Map<String, String> props = new HashMap<>();
		props.put("lang", "java");
		props.put("severity.level", "none");
		props.put("sonar.sources", "its/java");
		props.put("sonar.java.binaries", "build/its/java");
		props.put("rule.include", "java:S106");
		final Analysis a = Chirp.scan(props);
		assertEquals(1, a.findings().size());
	}

	@Test
	public void testRuleParameterKey() throws IOException {
		final Map<String, String> props = new HashMap<>();
		props.put("lang", "java");
		props.put("severity.level", "none");
		props.put("sonar.sources", "its/java");
		props.put("sonar.java.binaries", "build/its/java");
		props.put("rule.include", "java:S100");
		props.put("java:S100.format", "^[a-z][a-zA-Z0-9_]*$");
		final Analysis a = Chirp.scan(props);
		assertEquals(0, a.findings().size());
	}
	@Test
	public void testRuleParameterFile() throws IOException {
		final File f = new File("build/tmp/rule.param");
		try (FileWriter fw = new FileWriter(f)) {
			fw.write("java:S100.format = ^[a-z][a-zA-Z0-9_]*$");
			fw.flush();
		}
		final Map<String, String> props = new HashMap<>();
		props.put("lang", "java");
		props.put("severity.level", "none");
		props.put("sonar.sources", "its/java");
		props.put("sonar.java.binaries", "build/its/java");
		props.put("rule.include", "java:S100");
		props.put("rule.param.file", "build/tmp/rule.param");
		final Analysis a = Chirp.scan(props);
		assertEquals(0, a.findings().size());
		f.delete();
	}

	private void assertJsonFindings(File f) throws JsonSyntaxException, JsonIOException, FileNotFoundException {
		final Gson gson = new Gson();
		final JsonObject findings = gson.fromJson(new FileReader(f), JsonObject.class);
		final JsonArray a = findings.get("findings").getAsJsonArray();
		assertEquals("issue count", ruleKeys.size(), a.size());
		for (JsonElement e : a) {
			assertTrue("contains issue", ruleKeys.contains(e.getAsJsonObject().get("rule_key").getAsString()));
		}
	}

	@Test
	public void testConsole() throws IOException {
		final String command = "--lang java --sonar-sources its/java --sonar-java-binaries build/its/java";
		final PrintStream old = System.out;
		final ByteArrayOutputStream bos = new ByteArrayOutputStream();
		final PrintStream p = new PrintStream(bos);
		System.setOut(p);
		Chirp.main(command.split(" "));
		p.flush();
		final String output = new String(bos.toByteArray(), StandardCharsets.UTF_8);
		System.setOut(old);
		int count = 0;
		for (int i = 0; i < output.length();) {
			i = output.indexOf("+----- Finding ----->", i) + 1;
			if (i == 0) {
				break;
			}
			count++;
		}
		assertEquals("issue count", 3, count);
		for (String ruleKey : ruleKeys) {
			assertTrue("contains issue", output.contains(ruleKey));
		}
	}

	@Test
	public void qualityTest() throws IOException {
		final String libraryPaths = Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
				.filter(s -> Files.exists(Paths.get(s)))
				.collect(Collectors.joining(","));
		final Map<String, String> properties = new HashMap<>();
		properties.put("lang", "java");
		properties.put("severity.level", "major");
		properties.put("rule.exclude.file", ".chirp/rule.exclude");
		properties.put("sonar.sources", "src/main/java");
		properties.put("sonar.java.binaries", "build/classes/java/main");
		properties.put("sonar.java.libraries", libraryPaths);
		properties.put("sonar.tests", "src/test/java");
		properties.put("sonar.java.test.binaries", "build/classes/java/test");
		properties.put("sonar.java.test.libraries", libraryPaths);
		final Analysis a = Chirp.scan(properties);
		assertEquals("Unused Ignores " + a.unusedIgnores().toString(), 0, a.unusedIgnores().size());
		assertEquals(a.findings().stream().map(f -> System.lineSeparator() + f.message()).collect(Collectors.joining()), 0, a.findings().size());
	}
}
