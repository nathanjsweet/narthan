package com.github.nathanjsweet.narthan;

import java.util.Base64;
import java.util.TreeMap;
import java.util.Map;

import java.nio.charset.StandardCharsets;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.Writer;
import java.io.UnsupportedEncodingException;

import java.net.URLDecoder;

import com.amazonaws.auth.BasicAWSCredentials;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.ParseException;
import org.json.simple.parser.JSONParser;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.MessageDigest;

public class Application implements RequestStreamHandler {
	
	private static final String DOMAIN = "DOMAIN";
	private static final String HMAC_SHA1 = "HmacSHA1";
	private static final String AWS_SNS_KEY = "AWS_SNS_KEY";
	private static final String AWS_SNS_SECRET = "AWS_SNS_SECRET";
	
	JSONParser parser = new JSONParser();

	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
		LambdaLogger logger = context.getLogger();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		try {
			String authToken = null;
			String domain = null;
			JSONObject event = (JSONObject)parser.parse(reader);
			JSONObject pps = (JSONObject)event.get("pathParameters");
			
			if (pps == null || pps.get("number") == null) {
				finishRequest(outputStream, "400", null);
				return;
			}
			String number = (String)pps.get("number");
			String numberKey = "p".concat(number);

			authToken = System.getenv(numberKey);
			if (authToken == null) {
				logger.log(String.format("attempted request with non-existent number %s", number));
				finishRequest(outputStream, "404", null);
				return;
			}
			
			domain = System.getenv(DOMAIN);
			if (domain == null) {
				logger.log("missing domain environment variable for application");
				finishRequest(outputStream, "500", null);
				return;
			}
			JSONObject headers = (JSONObject)event.get("headers");
			String path = (String)event.get("path");
			String body = (String)event.get("body");
			if (headers == null || headers.get("X-Twilio-Signature") == null || body == null  || path == null) {
				logger.log("\"X-Twilio-Signature\" missing");
				finishRequest(outputStream, "400", null);
				return;
			}
			String twilioSig = (String)headers.get("X-Twilio-Signature");
			if (body == null || path == null) {
				logger.log("body or path missing");
				finishRequest(outputStream, "400", null);
				return;
			}
			TreeMap<String, String> postBody = splitQuery(body);
			String reqBody = createRequestBody(domain, path, null, postBody);
			if (!validateSignature(reqBody, authToken, twilioSig)) {
				logger.log("\"X-Twilio-Signature\" was invalid for request body");
				logger.log(reqBody);
				finishRequest(outputStream, "400", null);
				return;
			}
			routeRequest(logger, domain, postBody);
		} catch(ParseException pex) {
			finishRequest(outputStream, "400", pex.toString());
			return;
		} catch(Exception ex) {
			logger.log(ex.toString());
			finishRequest(outputStream, "500", null);
			return;
		}
		finishRequest(outputStream, "204", null);

	}

	private void finishRequest(OutputStream outputStream, String responseCode, String err) throws IOException {
		JSONObject responseJson = new JSONObject();
		responseJson.put("statusCode", responseCode);
		if (err != null) {
			responseJson.put("exception", err);
		}
		OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
		writer.write(responseJson.toJSONString());  
		writer.close();
	}

	private static TreeMap<String, String> splitQuery(String query) throws UnsupportedEncodingException {
		TreeMap<String, String> query_pairs = new TreeMap<String, String>((String a, String b)-> a.compareTo(b));
		String[] pairs = query.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf("=");
			query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
		}
		return query_pairs;
	}

	private static String createRequestBody(String domain, String path, String query, TreeMap<String, String> body) {
		StringBuilder sb = new StringBuilder();
		sb.append(domain);
		sb.append(path);
		if (query != null) {
			sb.append(query);
		}
		if (body != null) {
			for (Map.Entry<String, String> entry : body.entrySet()) {
				sb.append(entry.getKey());
				sb.append(entry.getValue());
			}
		}
		return sb.toString();
	}

	private static boolean validateSignature(String request, String authToken, String sig) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(authToken.getBytes(), HMAC_SHA1);
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(signingKey);
		byte[] digest = Base64.getEncoder().encode(mac.doFinal(request.getBytes(StandardCharsets.UTF_8)));
		return MessageDigest.isEqual(digest, sig.getBytes());
	}

	private static void routeRequest(LambdaLogger logger, String domainNumber, TreeMap<String, String> request) {
		logger.log(String.format("domain number: %s", domainNumber));
		StringBuilder sb = new StringBuilder("BODY:\n{");
		for (Map.Entry<String, String> entry : request.entrySet()) {
			sb.append(String.format("\n\t\"%s\":\"%s\",", entry.getKey(), entry.getValue()));
		}
		sb.append("\n}");
		logger.log(sb.toString());
	}

}
