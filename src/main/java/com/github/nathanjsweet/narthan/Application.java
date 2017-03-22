package com.github.nathanjsweet.narthan;

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

public class Application implements RequestStreamHandler {
	
	JSONParser parser = new JSONParser();

	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
		LambdaLogger logger = context.getLogger();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		JSONObject responseJson = new JSONObject();
		try {
			JSONObject event = (JSONObject)parser.parse(reader);
			logger.log(event.toJSONString());
				/*JSONObject pps = (JSONObject)event.get("pathParameters");
			if (pps != null && pps.get("number") != null) {
				String numberKey = "p"+pps.get("number");
				String authToken = System.getenv(numberKey)
			}
			

			JSONObject responseBody = new JSONObject();
			responseBody.put("input", event.toJSONString());
			responseBody.put("message", "Hello " + name + "!");

			JSONObject headerJson = new JSONObject();
			headerJson.put("x-custom-response-header", "my custom response header value");

			responseJson.put("statusCode", responseCode);
			responseJson.put("headers", headerJson);
			responseJson.put("body", responseBody.toString());  */

		} catch(ParseException pex) {
			responseJson.put("statusCode", "400");
			responseJson.put("exception", pex);
		}
		responseJson.put("statusCode", "204");
		logger.log(responseJson.toJSONString());
		OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
		writer.write(responseJson.toJSONString());  
		writer.close();
	}


}
