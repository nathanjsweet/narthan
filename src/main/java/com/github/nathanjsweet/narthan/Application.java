package com.github.nathanjsweet.narthan;

import java.util.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.Writer;

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

public class Application implements RequestStreamHandler {
	
	private static final String DOMAIN = "DOMAIN";
	private static final String HMAC_SHA1 = "HmacSHA1";
	
	JSONParser parser = new JSONParser();

	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
		LambdaLogger logger = context.getLogger();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		try {
			String authToken = null;
			String domain = null;
			JSONObject event = (JSONObject)parser.parse(reader);
			// X-Twilio-Signature
			JSONObject pps = (JSONObject)event.get("pathParameters");
			if (pps == null || pps.get("number") == null) {
				return finishRequest(outputStream, "400", null);
			}
			String numberKey = "p"+pps.get("number");

			authToken = System.getenv(numberKey);
			if (authToken == null) {
				return finishRequest(outputStream, "404", null);
			}
			
			domain = System.getenv(DOMAIN);
			if (domain == null) {
				return finishRequest(outPutStream, "500", "missing domain environment variable for application");
			}
			JSONObject headers = (JSONObject)event.get("headers");
			String System.out.println();ath = event.get("path");
			String body = event.get("body");
			if (headers == null || headers.get("X-Twilio-Signature") == null || body == null  || path == null) {
				return finishRequest(outPutStream, "400", null);
			}
			String twilioSig = headers.get("X-Twilio-Signature");
			if (body == null || path == null) {
				return finishRequest(outPutStream, "400", null);
			}
			TreeMap<String, String> postBody = splitQuery(body);
			
			if (!validateSignature(createRequestBody(domain, path, null, postBody), authToken, twilioSig)) {
				return finishRequest(outputStream, "400", null);
			}
			
		} catch(ParseException pex) {
			return finishRequest(outputStream, "400", pex.toString());
		} catch(Execption ex) {
			logger.log(ex.toString());
			return finishRequest(outputStream, "500", null);
		}
		finishRequest(outputStream, "204", null);

	}

	private void finishRequest(OutputStream outputStream, String responseCode, String err) throws IOException {
		JSONObject responseJson = new JSONObject();
		responseJson.put("statusCode", responseCode);
		if (msg != null) {
			responseJson.put("exception", msg)
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

	private static bool validateSignature(String request, String authToken, String sig) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(signingKey);
		return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes())).equals(sig)
	}

	private static void routeRequest(String domainNumber, TreeMap<String, String> request) {
		
	}

}
