package io.github.spinsie.chirp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;

public class AnalyzerTests {

	@BeforeClass
	public static void setup() throws InterruptedException, IOException {
		final ProcessBuilder pb = new ProcessBuilder(Arrays.asList("javac", "-d", "build/its/java", "its/java/Test.java"));
		assertEquals("Compilation", 0, pb.start().waitFor());
	}

	@Test
	public void testJava() throws IOException {
		final String command = "--lang java --sonar-sources its/java --sonar-java-binaries build/its/java --output-file build/its/java/findings.json";
		Analyzer.main(command.split(" "));
		final Gson gson = new Gson();
		final JsonObject findings = gson.fromJson(new FileReader(Paths.get("build/its/java/findings.json").toFile()), JsonObject.class);
		final List<String> ruleKeys = Arrays.asList("java:S1220", "java:S106", "java:S100");
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
		try {
			Analyzer.main(command.split(" "));
			p.flush();
			final String output = new String(bos.toByteArray(), StandardCharsets.UTF_8);
			int count = 0;
			for (int i = 0; i < output.length();) {
				i = output.indexOf("+----- Finding ----->", i) + 1;
				if (i == 0) {
					break;
				}
				count++;
			}
			assertEquals("issue count", 3, count);
		} finally {
			System.setOut(old);
		}
	}
}