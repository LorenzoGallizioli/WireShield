package com.wireshield.av;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wireshield.enums.warningClass;
import com.wireshield.localfileutils.FileManager;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.HttpClient;
import org.apache.http.HttpResponse;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.client.utils.URIBuilder;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.util.Queue;
import java.util.LinkedList;

/*
 * The VirusTotal class interacts with the VirusTotal API to analyze files for
 * potential threats. It calculates file hashes, uploads files for analysis, and
 * retrieves analysis reports.
 */
public class VirusTotal {
	private String API_KEY; // API Key for accessing the VirusTotal API
	static final int REQUEST_LIMIT = 4; // Maximum requests allowed per minute
	private static final long ONE_MINUTE_IN_MILLIS = 60 * 1000; // Duration of one minute in milliseconds
	Queue<Long> requestTimestamps = new LinkedList<>(); // Tracks timestamps of API requests
	private ScanReport scanReport; // Stores the scan report for the last analyzed file

	/*
	 * Constructs a VirusTotal instance and ensures the API key file is available.
	 * If the key is invalid or missing, the program prompts the user for input.
	 */
	public VirusTotal() {
		ensureApiKeyFileExists(); // Ensures the API key file is created or requests input if missing
		this.API_KEY = getApiKey(); // Reads the API key from the file
		if (this.API_KEY == null || this.API_KEY.trim().isEmpty()) {
			System.out.println("Error: Invalid API key. Restart the program and enter a valid key.");
			System.exit(1);
		}
	}

	/**
	 * Analyzes a file by uploading it to VirusTotal for a threat analysis. If the
	 * request limit is exceeded or the file is invalid, sets an invalid ScanReport.
	 *
	 * @param file The file to analyze.
	 */
	public void analyze(File file) {
		// Check request limits
		if (!canMakeRequest()) {
			System.out.println("VirusTotal analysis canceled. Proceeding with ClamAV check only.");
			scanReport = new ScanReport();
			scanReport.setValid(false);
			scanReport.setThreatDetails("VirusTotal analysis rejected: request limit exceeded.");
			return;
		}

		// Validate the file
		if (file == null || !file.exists()) {
			System.out.println("The file does not exist.");
			scanReport = new ScanReport();
			scanReport.setValid(false);
			return;
		}

		String fileHash = FileManager.calculateSHA256(file);
		if (fileHash != null) {
			System.out.println("SHA256 calculated: " + fileHash);
		} else {
			System.out.println("Error calculating SHA256.");
		}

		try {
			// Build the HTTP POST request
			HttpClient client = HttpClients.createDefault();
			URI uri = new URIBuilder("https://www.virustotal.com/api/v3/files").build();
			HttpPost post = new HttpPost(uri);
			post.addHeader("x-apikey", API_KEY);

			MultipartEntityBuilder builder = MultipartEntityBuilder.create();
			builder.addPart("file", new FileBody(file));
			post.setEntity(builder.build());

			HttpResponse response = client.execute(post);
			int statusCode = response.getStatusLine().getStatusCode();

			if (statusCode == 200) {
				InputStream responseStream = response.getEntity().getContent();
				ObjectMapper objectMapper = new ObjectMapper();
				JsonNode responseJson = objectMapper.readTree(responseStream);
				String scanId = responseJson.path("data").path("id").asText();

				System.out.println("Analysis completed. Scan ID: " + scanId);
				scanReport = new ScanReport(scanId, file);
				scanReport.setSha256(fileHash);

				// Record the timestamp of the request
				requestTimestamps.add(System.currentTimeMillis());
			} else {
				System.out.println("Error during analysis. HTTP Status Code: " + statusCode);
				scanReport = new ScanReport();
				scanReport.setValid(false);
				scanReport.setThreatDetails("Error analyzing the file.");
			}
		} catch (Exception e) {
			e.printStackTrace();
			scanReport = new ScanReport();
			scanReport.setValid(false);
			scanReport.setThreatDetails("Error analyzing the file.");
		}
	}

	/**
	 * Retrieves the analysis report for the previously uploaded file. Polls the
	 * VirusTotal API until the analysis is complete.
	 *
	 * @return The ScanReport containing the analysis results, or null if an error
	 *         occurred.
	 */
	public ScanReport getReport() {
		// Ensure a valid scan report exists
		if (scanReport == null || scanReport.getScanId() == null) {
			System.out.println("No report available. Please perform an analysis first.");
			return null;
		}

		try {
			HttpClient client = HttpClients.createDefault();
			URI uri = new URIBuilder("https://www.virustotal.com/api/v3/analyses/" + scanReport.getScanId()).build();

			boolean isCompleted = false;
			while (!isCompleted) {
				HttpGet get = new HttpGet(uri);
				get.addHeader("x-apikey", API_KEY);

				HttpResponse response = client.execute(get);
				int statusCode = response.getStatusLine().getStatusCode();

				if (statusCode == 200) {
					InputStream responseStream = response.getEntity().getContent();
					ObjectMapper objectMapper = new ObjectMapper();
					JsonNode responseJson = objectMapper.readTree(responseStream);

					JsonNode attributesNode = responseJson.path("data").path("attributes");

					String status = attributesNode.path("status").asText("Status not found");

					if ("completed".equalsIgnoreCase(status)) {
						// Parse the statistics
						JsonNode statsNode = attributesNode.path("stats");

						int maliciousCount = statsNode.path("malicious").asInt();
						int harmlessCount = statsNode.path("harmless").asInt();
						int suspiciousCount = statsNode.path("suspicious").asInt();
						int undetectedCount = statsNode.path("undetected").asInt();

						scanReport.setValid(true);
						scanReport.setMaliciousCount(maliciousCount);
						scanReport.setHarmlessCount(harmlessCount);
						scanReport.setSuspiciousCount(suspiciousCount);
						scanReport.setUndetectedCount(undetectedCount);

						// Determine the threat level
						if (maliciousCount > 0) {
							double totalScans = maliciousCount + harmlessCount + suspiciousCount + undetectedCount;
							double maliciousPercentage = (maliciousCount / totalScans) * 100;

							scanReport.setThreatDetected(true);

							if (maliciousPercentage > 70 || maliciousCount > 50) {
								scanReport.setWarningClass(warningClass.DANGEROUS);
								scanReport.setThreatDetails("High risk: high percentage of malicious detections.");
							} else {
								scanReport.setWarningClass(warningClass.SUSPICIOUS);
								scanReport.setThreatDetails("Moderate risk: the file might be harmful.");
							}
						} else {
							scanReport.setThreatDetected(false);
							scanReport.setWarningClass(warningClass.CLEAR);
							scanReport.setThreatDetails("The file is clean: no threats detected.");
						}
						isCompleted = true;
					} else {
						Thread.sleep(5000);
					}
				} else {
					System.out.println("Error retrieving the report: " + statusCode);
					scanReport = new ScanReport();
					scanReport.setValid(false);
					isCompleted = true;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			scanReport = new ScanReport();
			scanReport.setValid(false);
			scanReport.setThreatDetails("Error during report retrieval.");
		}

		return scanReport;
	}

	/**
	 * Reads the API key from the api_key.txt file.
	 *
	 * @return The API key as a String, or null if the file is empty or missing.
	 */
	String getApiKey() {
		String filePath = "api_key.txt";
		String apiKey = FileManager.readFile(filePath);
		if (apiKey != null) {
			return apiKey.trim(); // Remove extra spaces
		}
		return null;
	}

	/*
	 * Ensures that the api_key.txt file exists. If the file does not exist or is
	 * empty, prompts the user to enter the API key and saves it to the file.
	 */
	void ensureApiKeyFileExists() {
		String filePath = "api_key.txt";

		if (!FileManager.createFile(filePath)) {
			String apiKeyContent = FileManager.readFile(filePath);
			if (apiKeyContent != null && !apiKeyContent.trim().isEmpty()) {
				System.out.println("API key already exists.");
				return;
			}
		}
		
		System.out.println("API key file is missing or empty. Please enter your API key:");
		java.util.Scanner scanner = null;
		try {
			scanner = new java.util.Scanner(System.in); // Initialize the Scanner
			String apiKey = scanner.nextLine(); // Read user input

			if (apiKey != null && !apiKey.trim().isEmpty()) { // Validate input
				if (FileManager.writeFile(filePath, apiKey)) {
					System.out.println("API key saved successfully!");
				} else {
					System.out.println("Error saving the API key."); // Handle file write error
					System.exit(1);
				}
			} else {
				System.out.println("Invalid API key. Restart the program and provide a valid key.");
				System.exit(1);
			}
		} catch (Exception e) {
			System.out.println("Error during API key input: " + e.getMessage()); // Handle exceptions
			System.exit(1);
		} finally {
			if (scanner != null) {
				scanner.close(); // Ensure Scanner is closed
			}
		}
	}

	/**
	 * Checks if a new API request can be made without exceeding the rate limit. If
	 * the limit is reached, informs the user about the remaining wait time.
	 *
	 * @return true if a request can be made, false otherwise.
	 */
	boolean canMakeRequest() {
		long currentTime = System.currentTimeMillis();

		// Remove timestamps older than one minute
		while (!requestTimestamps.isEmpty() && currentTime - requestTimestamps.peek() > ONE_MINUTE_IN_MILLIS) {
			requestTimestamps.poll();
		}

		// Check if the request limit has been reached
		if (requestTimestamps.size() < REQUEST_LIMIT) {
			return true;
		} else {
			long oldestRequestTime = requestTimestamps.peek();
			long timeToWait = ONE_MINUTE_IN_MILLIS - (currentTime - oldestRequestTime);
			System.out.println("Request limit exceeded! VirusTotal will be available in: " + (timeToWait / 1000) + " seconds.");
			return false;
		}
	}
}