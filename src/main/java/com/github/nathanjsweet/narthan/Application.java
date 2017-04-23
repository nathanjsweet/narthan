package com.github.nathanjsweet.narthan;
import java.lang.Long;

import java.util.Base64;
import java.util.TreeMap;
import java.util.Map;
import java.util.HashMap;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

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

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import com.amazonaws.auth.BasicAWSCredentials;

import com.amazonaws.services.lambda.AWSLambdaClient;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.model.ListTagsRequest;
import com.amazonaws.services.lambda.model.ListTagsResult;
import com.amazonaws.services.lambda.model.TagResourceRequest;


import com.amazonaws.services.sns.AmazonSNSClient;
import com.amazonaws.services.sns.model.ListSubscriptionsByTopicResult;
import com.amazonaws.services.sns.model.Subscription;
import com.amazonaws.services.sns.model.SubscribeRequest;
import com.amazonaws.services.sns.model.SubscribeResult;
import com.amazonaws.services.sns.model.CreateTopicRequest;
import com.amazonaws.services.sns.model.CreateTopicResult;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.ListSubscriptionsByTopicRequest;


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
	private static final String AWS_SNS_KEY = "AWS_KEY";
	private static final String AWS_SNS_SECRET = "AWS_SECRET";
	private static final String ADMIN_TOPIC_ARN = "ADMIN_TOPIC_ARN";
	private static final String LAMBDA_ARN = "LAMBDA_ARN";
	private static final String TWILIO_SID = "TWILIO_SID";
	private static final String TWILIO_AUTH = "TWILIO_AUTH";
	private static final String TWILIO_NUMBER = "TWILIO_NUMBER";
	
	private static final String NON_NUMERIC = "[\\D]";
	private static final String ALPHA_NUMERIC = "^[\\w]+$";
	private static final String TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages";

	private static BasicAWSCredentials AWSCreds = new BasicAWSCredentials(System.getenv(AWS_SNS_KEY), System.getenv(AWS_SNS_SECRET));
	private static AmazonSNSClient SNSClient = new AmazonSNSClient(AWSCreds);
	private static AWSLambdaClient LambdaClient = new AWSLambdaClient(AWSCreds);

	private static String Domain = System.getenv(DOMAIN);
	private static String AdminARN = System.getenv(ADMIN_TOPIC_ARN);
	private static String LambdaARN = System.getenv(LAMBDA_ARN);
	private static String TwilioSid = System.getenv(TWILIO_SID);
	private static String TwilioAuth = System.getenv(TWILIO_AUTH);
	private static String TwilioNumber = System.getenv(TWILIO_NUMBER);

	static {
		Twilio.init(TwilioSid, TwilioAuth);
	}
	
	private LambdaLogger logger = null;


	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
		logger = context.getLogger();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		String statusCode = "204";
		try {
			JSONParser parser = new JSONParser();
			JSONObject event = (JSONObject)parser.parse(reader);
			log("event: %s", event.toJSONString());
			if (TwilioAuth == null || TwilioSid == null) {
				throwException("twilio sid and/or auth environment variables not set");
			}
			if (Domain == null) {
				throwException("missing domain environment variable for application");
			}

			JSONObject headers = (JSONObject)event.get("headers");
			String path = (String)event.get("path");
			String body = (String)event.get("body");
			if (headers == null || headers.get("X-Twilio-Signature") == null || body == null  || path == null) {
				log("\"X-Twilio-Signature\" missing");
				finishRequest(outputStream, "400", null);
				return;
			}

			String twilioSig = (String)headers.get("X-Twilio-Signature");
			if (body == null || path == null) {
				log("body or path missing");
				finishRequest(outputStream, "400", null);
				return;
			}

			TreeMap<String, String> postBody = splitQuery(body);
			String reqBody = createRequestBody(path, null, postBody);
			if (!validateSignature(reqBody, twilioSig)) {
				log("\"X-Twilio-Signature\" was invalid for request body");
				log(reqBody);
				finishRequest(outputStream, "400", null);
				return;
			}

			statusCode = routeRequest(postBody);
		} catch(ParseException pex) {
			finishRequest(outputStream, "400", pex.toString());
			return;
		} catch(Exception ex) {
			log(ex.toString());
			finishRequest(outputStream, "500", null);
			return;
		}
		finishRequest(outputStream, statusCode, null);

	}

	private void log(String format, Object... args) {
		logger.log(String.format(format, args));
	}

	private static void throwException(String format, Object... args) throws Exception {
		throw new Exception(String.format(format, args));
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

	private static String createRequestBody(String path, String query, TreeMap<String, String> body) {
		StringBuilder sb = new StringBuilder();
		sb.append(Domain);
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

	private static boolean validateSignature(String request, String sig) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(TwilioAuth.getBytes(), HMAC_SHA1);
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(signingKey);
		byte[] digest = Base64.getEncoder().encode(mac.doFinal(request.getBytes(StandardCharsets.UTF_8)));
		return MessageDigest.isEqual(digest, sig.getBytes());
	}

	private String routeRequest(TreeMap<String, String> request) throws Exception {
		String to = request.get("To");
		if (to == null) {
			log("message is not to any specific number");
			return "400";
		}
		to = to.replaceAll(NON_NUMERIC, "");
		if (to.indexOf('1') == 0) {
			to = to.substring(1);
		}
		String body = request.get("Body");
		if (body == null) {
			log("no body in request");
			return "400";
		}
		body = body.trim();

		String from = request.get("From");
		if (from == null) {
			log("no from number");
			return "400";
		}
		from = from.replaceAll(NON_NUMERIC, "");
		boolean admin = isAdmin(from);
		
		String[] sp = body.split("\\s+", 2);
		String cmd = sp[0].toLowerCase();
		String realBody = null;
		if (sp.length > 1) {
			realBody = sp[1];
		}
		switch(cmd) {
		case "ayuda":
			if(admin) {
				ayuda(from, realBody, request);
			}
			break;
		case "subscribe":
			subscribe(from, realBody, request);
			break;
		case "unsubscribe":
			break;
		case "group":
			if(admin) {
				group(from, realBody, request);
			}
			break;
		}
		return "204";
	}

	private void ayuda(String to, String body, TreeMap<String, String> request) throws Exception {
		String cmd = "";
		String realBody = null;
		if (body != null) {
			String[] sp = body.split("\\s+", 2);
			cmd = sp[0].toLowerCase();
			if (sp.length > 1) {
				realBody = sp[1];
			}
		}
		StringBuilder sb = new StringBuilder();
		switch(cmd) {
		case "subscribe":
			sb.append("subscribe [group-name] [group-code]\n\n");
			sb.append("Subscribe to a group. The code you were given is only valid for 15 minutes.");
			break;
		case "unsubscribe":
			sb.append("unsubscribe [group-name]\n\n");
			sb.append("Unsubscribe from a group. You can use \"*\" to unsubscribe from all groups.");
			break;
		case "list":
			sb.append("list\n\n");
			sb.append("List all the groups you are in.");
			break;
		case "group":
			sb = groupAyuda(realBody);
			break;
		default:
			sb.append("ayuda [command]\n\n");
			sb.append("subscribe [group-name] [group-code]\n\n");
			sb.append("unsubscribe [group-name]");
			sb.append("list\n\n");
			sb.append("group [group-command] ...");
			break;
		}
		sendTwilioMessage(to, sb.toString());

	}

	private StringBuilder groupAyuda(String body) {
		String cmd = "";
		if (body != null) {
			String[] sp = body.split("\\s+", 2);
			cmd = sp[0].toLowerCase();
		}
		StringBuilder sb = new StringBuilder();
		switch(cmd) {
		case "text":
			sb.append("group text [name] [text]\n\n");
			sb.append("Send a text to a specific group.");
			break;
		case "code":
			sb.append("group code [name]\n\n");
			sb.append("Get a code, valid for 15 minutes, that will allow people to subscribe to a group.");
			break;
		case "unsubscribe":
			sb.append("group unsubscribe [name] [number]\n\n");
			sb.append("Unsubscribe a specific phone number from a group.");
			break;
		case "create":
			sb.append("group create [name]\n\n");
			sb.append("Create a new group. The name must contain only letters and numbers and must be all lower case. This command will have no effect if the group already exists.");
			break;
		case "delete":
			sb.append("group delete [name]\n\n");
			sb.append("Delete a group. Be careful with this command it will not ask you to confirm the delete, it will just do it.");
			break;
		case "list":
			sb.append("group list\n\n");
			sb.append("List all the groups.\n\n");
			break;
		default:
			sb.append("group text [name] [text]\n\n");
			sb.append("group code [name]\n\n");
			sb.append("group unsubscribe [name] [number]\n\n");
			sb.append("group create [name]\n\n");
			sb.append("group delete [name]\n\n");
			sb.append("group list");
			break;
		}
		return sb;
	}
	private void subscribe(String to, String body, TreeMap<String, String> request) throws Exception {
		String[] sp = body.split("\\s+");
		if (sp.length < 2) {
			log("subscribe request from %s sent without group or code");
			return;
		}
		String group = sp[0].toLowerCase();
		String code = sp[1].trim();
		Map<String, String> meta = getGroupMeta(group);
		if (meta == null) {
			log("subsribe attempted on group %s, with no code", group);
			return;
		}
		String expires = meta.get("expires");
		if (expires == null) {
			log("meta data on group %s without expiration", group);
			return;
		}
		long exp = Long.parseLong(expires, 10);
		if ((new Date()).getTime() >= exp) {
			log("subscribe attempt on expired code for group %s", group);
			return;
		}
		String c = meta.get("code");
		if (c == null) {
			throwException("meta data on group %s missing code", group);
		}
		String arn = meta.get("arn");
		if (arn == null) {
			throwException("meta data on group %s missing arn", group);
		}
		if (code.equals(c)) {
			SNSClient.subscribe(new SubscribeRequest(arn, "sms", to));
			sendTwilioMessage(to, String.format("You are now subscribed to %s.", group));
		}
	}

	private void group(String to, String body, TreeMap<String, String> request) throws Exception {
		if (body == null) {
			ayuda(to, "group", request);
			return;
		}
		String[] sp = body.split("\\s+", 2);
		if (sp.length < 2) {
			log("group command sent without any text");
			ayuda(to, "group", request);
			return;
		}
		String cmd = sp[0].toLowerCase();
		String realBody = sp[1].trim();
		switch(cmd){
		case "text":
			groupText(to, realBody, request);
			break;
		case "code":
			groupCode(to, realBody, request);
			break;
		case "unsubscribe":
			// unimplemented
			break;
		case "create":
			groupCreate(to, realBody, request);
			// blah
			break;
		case "delete":
			// unimplemented
			break;
		case "list":
			//blah
			break;
		default:
			ayuda(to, "group", request);
			return;
		}
	}

	private void groupText(String to, String body, TreeMap<String, String> request) throws Exception {
		String[] sp = body.split("\\s+", 2);
		if (sp.length < 2) {
			ayuda(to, "group text", request);
			return;
		}
		String groupName = sp[0].toLowerCase();
		String realBody = sp[1];
		Map<String, String> meta = null;
		try {
			meta = getGroupMeta(groupName);
		} catch (Exception e) {
			log(e.toString());
			meta = null;
		}
		if (meta == null) {
			log("group text command sent for non existent group %s", groupName);
			sendTwilioMessage(to, String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
			return;
		}
		String arn = meta.get("arn");
		if (arn == null) {
			log("could not find group arn for group %s for a group text command", groupName);
			sendTwilioMessage(to, String.format("It looks like the group %s exists, but it is malformed in the system, please call the administrator/owner to fix it.", groupName));
		}
		boolean success = true;
		try {
			SNSClient.publish(new PublishRequest(arn, realBody));
		} catch(Exception e) {
			log(e.toString());
			success = false;
		}
		if (!success) {
			sendTwilioMessage(to, String.format("I'm sorry I ran into an error trying to send your text to group %s. Please contact the administrator to fix it.", groupName));
			return;
		}
		sendTwilioMessage(to, String.format("I sent your text to group %s.", groupName));
	}

	private void groupCode(String to, String body, TreeMap<String, String> request) throws Exception {
		Map<String, String> meta = null;
		String groupName = body.toLowerCase();
		try {
			meta = getGroupMeta(groupName);
		} catch (Exception e) {
			log(e.toString());
			meta = null;
		}
		if (meta == null) {
			log("group text command sent for non existent group %s", groupName);
			sendTwilioMessage(to, String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
			return;
		}
		String arn = meta.get("arn");
		if (arn == null) {
			log("could not find group arn for group %s for a group text command", groupName);
			sendTwilioMessage(to, String.format("It looks like the group %s exists, but it is malformed in the system, please call the administrator/owner to fix it.", groupName));
		}
		String code = meta.get("code");
		if (code != null) {
			String expires = meta.get("expires");
			if (expires != null) {
				long exp = Long.parseLong(expires, 10);
				if ((new Date()).getTime() >= exp) {
					code = null;
				}
			} else {
				code = null;
			}
		}
		if (code == null) {
			code = "example";
			meta.put("code", code);
		}
		meta.put("expires", Long.toString((new Date()).getTime()+(1000*60*15)));
		boolean success = true;
		try {
			setGroupMeta(groupName, meta);
		} catch(Exception e) {
			log(e.toString());
			success = false;
		}
		if (!success) {
			sendTwilioMessage(to, String.format("There was an error setting the subscribe code for %s, try again in a few seconds. If the problem persists contact the administrator to fix the issue.", groupName));
			return;
		}
		sendTwilioMessage(to, String.format("The subscribe code (for the next 15 minutes) for %s is \"%s\"", groupName, code));
	}

	private void groupCreate(String to, String body, TreeMap<String, String> request) throws Exception {
		body = body.toLowerCase();
		if (!body.matches(ALPHA_NUMERIC)) {
			ayuda(to, "group create", request);
			return;
		}
		boolean success = true;
		CreateTopicResult ctr = null;
		String groupName = body;
		try {
			ctr = SNSClient.createTopic(new CreateTopicRequest(groupName));
		} catch(Exception e) {
			log(e.toString());
			success = false;
		}
		if (!success) {
			sendTwilioMessage(to, String.format("There was an error creating the group %s. Contact the administrator to fix it.", groupName));
			return;
		}
		try {
			HashMap map = new HashMap();
			map.put("arn", ctr.getTopicArn());
			setGroupMeta(groupName, map);
		} catch(Exception e) {
			log(e.toString());
			success = false;
		}
		if (!success) {
			sendTwilioMessage(to, String.format("There was an error creating the group %s. Contact the administrator to fix it.", groupName));
			return;
		}
		sendTwilioMessage(to, String.format("Successfully created the group %s", groupName));
		
	}

	private void sendTwilioMessage(String to, String body) throws Exception {
		Message message = Message.creator(new PhoneNumber(to), new PhoneNumber(TwilioNumber), body).create();
		log("message sid: %s", message.getSid());
	}

	private static boolean isAdmin(String number) throws Exception {
		ListSubscriptionsByTopicRequest tr = new ListSubscriptionsByTopicRequest();
		tr.setTopicArn(AdminARN);
		ListSubscriptionsByTopicResult res = SNSClient.listSubscriptionsByTopic(tr);
		List<Subscription> subs = res.getSubscriptions();
		String nextToken = res.getNextToken();
		while(nextToken != null) {
			ListSubscriptionsByTopicRequest tr2 = new ListSubscriptionsByTopicRequest();
			tr2.setTopicArn(AdminARN);
			tr2.setNextToken(nextToken);
			ListSubscriptionsByTopicResult resN = SNSClient.listSubscriptionsByTopic(tr2);
			subs.addAll(resN.getSubscriptions());
			nextToken = resN.getNextToken();
		}
		for(Subscription sub : subs) {
			if(sub.getEndpoint().replaceAll(NON_NUMERIC, "").equals(number)) {
				return true;
			}
		}
		return false;
	}

	private static Map<String,String> getGroupMeta(String group) throws Exception {
		ListTagsRequest ltr = new ListTagsRequest();
		ltr.setResource(LambdaARN);
		ListTagsResult res = LambdaClient.listTags(ltr);
		Map<String, String> tags = res.getTags();
		String meta = tags.get(group);
		if (meta != null) {
			JSONObject obj = decodeJSONTag(meta);
			Map<String, String> map = new HashMap<String, String>();
			Iterator<String> keysItr = obj.keySet().iterator();
			while(keysItr.hasNext()) {
				String key = keysItr.next();
				map.put(key, (String)obj.get(key));
			}
			return map;
		}
		return null;
	}

	private static void setGroupMeta(String group, Map<String, String> meta) throws Exception {
		TagResourceRequest trr = new TagResourceRequest();
		trr.setResource(LambdaARN);
		JSONObject obj = new JSONObject();
		for (Map.Entry<String, String> entry : meta.entrySet()) {
			obj.put(entry.getKey(), entry.getValue());
		}
		trr.addTagsEntry(group, encodeJSONTag(obj.toJSONString()));
		LambdaClient.tagResource(trr);
		
	}

	private static String encodeJSONTag(String json) throws Exception {
		return new String(Base64.getEncoder().encode(json.getBytes()), "UTF-8");
	}

	private static JSONObject decodeJSONTag(String json) throws Exception {
		String s = new String(Base64.getDecoder().decode(json.getBytes()), "UTF-8");
		JSONParser parser = new JSONParser();
		return (JSONObject)parser.parse(s);
	}
}



