package com.github.nathanjsweet.narthan;

import java.lang.Long;

import java.util.Base64;
import java.util.Collection;
import java.util.TreeMap;
import java.util.Map;
import java.util.HashMap;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

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

import com.amazonaws.services.lambda.AWSLambdaClient;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.model.ListTagsRequest;
import com.amazonaws.services.lambda.model.ListTagsResult;
import com.amazonaws.services.lambda.model.TagResourceRequest;
import com.amazonaws.services.lambda.model.UntagResourceRequest;

import com.amazonaws.services.sns.AmazonSNSClient;
import com.amazonaws.services.sns.model.ListSubscriptionsByTopicResult;
import com.amazonaws.services.sns.model.Subscription;
import com.amazonaws.services.sns.model.SubscribeRequest;
import com.amazonaws.services.sns.model.SubscribeResult;
import com.amazonaws.services.sns.model.CreateTopicRequest;
import com.amazonaws.services.sns.model.CreateTopicResult;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.ListSubscriptionsByTopicRequest;
import com.amazonaws.services.sns.model.ListSubscriptionsResult;
import com.amazonaws.services.sns.model.ListSubscriptionsRequest;
import com.amazonaws.services.sns.model.ListTopicsResult;
import com.amazonaws.services.sns.model.ListTopicsRequest;
import com.amazonaws.services.sns.model.DeleteTopicRequest;
import com.amazonaws.services.sns.model.DeleteTopicResult;
import com.amazonaws.services.sns.model.UnsubscribeRequest;
import com.amazonaws.services.sns.model.Topic;

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
	private static final String[] RANDOM_CHARS = {"B", "C", "D", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "V", "W", "X","Z", "2", "4", "5", "6", "7", "8", "9"};

	private static BasicAWSCredentials AWSCreds = new BasicAWSCredentials(System.getenv(AWS_SNS_KEY), System.getenv(AWS_SNS_SECRET));
	private static AmazonSNSClient SNSClient = new AmazonSNSClient(AWSCreds);
	private static AWSLambdaClient LambdaClient = new AWSLambdaClient(AWSCreds);

	private static String Domain = System.getenv(DOMAIN);
	private static String AdminARN = System.getenv(ADMIN_TOPIC_ARN);
	private static String LambdaARN = System.getenv(LAMBDA_ARN);
	private static String TwilioSid = System.getenv(TWILIO_SID);
	private static String TwilioAuth = System.getenv(TWILIO_AUTH);
	private static String TwilioNumber = System.getenv(TWILIO_NUMBER);

	private static interface SubscriptionOperator {
		public boolean op(Subscription sub);
	}

	private static class Response {
		public String[] Messages;
		
		public Response(String ...messages) {
			Messages = messages;
		}

		public String toXMLString() {
			StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<Response>");
			for (String msg : Messages) {
				sb.append("\n\t<Message>");
				sb.append(msg);
				sb.append("</Message>");
			}
			sb.append("\n</Response>");
			return sb.toString();
		}
	}

	private LambdaLogger logger = null;


	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
		logger = context.getLogger();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		Response res = null;
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
				finishRequest(outputStream, null);
				return;
			}

			String twilioSig = (String)headers.get("X-Twilio-Signature");
			if (body == null || path == null) {
				log("body or path missing");
				finishRequest(outputStream, null);
				return;
			}

			TreeMap<String, String> postBody = splitQuery(body);
			String reqBody = createRequestBody(path, null, postBody);
			if (!validateSignature(reqBody, twilioSig)) {
				log("\"X-Twilio-Signature\" was invalid for request body");
				log(reqBody);
				finishRequest(outputStream, null);
				return;
			}
			res = routeRequest(postBody);
		} catch(Exception ex) {
			log(ex.toString());
			finishRequest(outputStream, null);
			return;
		}
		finishRequest(outputStream, res);

	}

	private void log(String format, Object... args) {
		logger.log(String.format(format, args));
	}

	private static void throwException(String format, Object... args) throws Exception {
		throw new Exception(String.format(format, args));
	}

	private void finishRequest(OutputStream outputStream, Response res) throws IOException {
		JSONObject responseJson = new JSONObject();
		if(res == null) {
			responseJson.put("statusCode", "204");
		} else {
			responseJson.put("statusCode", "200");
			JSONObject headers = new JSONObject();
			headers.put("Content-Type", "application/xml");
			responseJson.put("headers", headers);
			responseJson.put("body", res.toXMLString());
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

	private Response routeRequest(TreeMap<String, String> request) throws Exception {
		String to = request.get("To");
		if (to == null) {
			log("message is not to any specific number");
			return null;
		}
		to = to.replaceAll(NON_NUMERIC, "");
		if (to.indexOf('1') == 0) {
			to = to.substring(1);
		}
		String body = request.get("Body");
		if (body == null) {
			log("no body in request");
			return null;
		}
		body = body.trim();

		String from = request.get("From");
		if (from == null) {
			log("no from number");
			return null;
		}
		from = from.replaceAll(NON_NUMERIC, "");
		boolean admin = isAdmin(from);
		
		String[] sp = body.split("\\s+", 2);
		String cmd = sp[0].toLowerCase();
		String realBody = null;
		if (sp.length > 1) {
			realBody = sp[1].trim();
		}
		switch(cmd) {
		case "ayuda":
			if(admin) {
				return ayuda(from, realBody);
			}
			break;
		case "subscribe":
			return subscribe(from, from, realBody, admin);
		case "unsubscribe":
			return unsubscribe(from, from, realBody, admin);
		case "group":
			if(admin) {
				return group(from, realBody);
			}
			break;
		}
		return null;
	}

	private Response ayuda(String to, String body) throws Exception {
		String cmd = "";
		String realBody = null;
		if (body != null) {
			String[] sp = body.split("\\s+", 2);
			cmd = sp[0].toLowerCase();
			if (sp.length > 1) {
				realBody = sp[1].trim();
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
		case "group":
			sb = groupAyuda(realBody);
			break;
		default:
			sb.append("ayuda [command]\n\n");
			sb.append("subscribe [group-name] [group-code]\n\n");
			sb.append("unsubscribe [group-name]\n\n");
			sb.append("group [group-command] ...");
			break;
		}
		return new Response(sb.toString());

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
			sb.append("group list [name]\n\n");
			sb.append("List all the groups, or numbers in a particular group.\n\n");
			break;
		default:
			sb.append("group text [name] [text]\n\n");
			sb.append("group code [name]\n\n");
			sb.append("group subscribe [name] [number]\n\n");
			sb.append("group unsubscribe [name] [number]\n\n");
			sb.append("group create [name]\n\n");
			sb.append("group delete [name]\n\n");
			sb.append("group list [name]");
			break;
		}
		return sb;
	}
	
	private Response subscribe(String to, String number, String body, boolean admin) throws Exception {
		String group = null;
		String code = null;
		if (!admin) {
			String[] sp = body.split("\\s+");
			if (sp.length < 2) {
				log("subscribe request from %s sent without group or code", to);
				return null;
			}
			group = sp[0].toLowerCase();
			code = sp[1].toLowerCase();
		} else {
			group = body.toLowerCase();
		}
		Map<String, String> meta = getGroupMeta(group);
		if (meta == null) {
			log("subsribe attempted on group %s, with no meta data", group);
			return null;
		}
		if (!admin) {
			String expires = meta.get("expires");
			if (expires == null) {
				log("meta data on group %s without expiration", group);
				return null;
			}
			long exp = Long.parseLong(expires, 10);
			if ((new Date()).getTime() >= exp) {
				log("subscribe attempt on expired code for group %s", group);
				return null;
			}
			String c = meta.get("code");
			if (c == null) {
				throwException("meta data on group %s missing code", group);
			}
			if (code.equals(c)) {
				log("subscribe attempt on invalid code for group %s", group);
				return null;
			}
		}
		String arn = meta.get("arn");
		if (arn == null) {
			throwException("meta data on group %s missing arn", group);
		}
		try {
			SNSClient.subscribe(new SubscribeRequest(arn, "sms", number));
		} catch(Exception e) {
			log(e.toString());
			if(admin) {
				return new Response("There was an error creating this subscription. Perhaps the number is invalid.");
			}
			return null;
		}
		String who = to.equals(number) ? "You are" : number.concat(" is");
		return new Response(String.format("%s now subscribed to %s.", who, group));
	}

	private Response unsubscribe(String to, String number, String body, boolean admin) throws Exception {
		body = body.trim().toLowerCase();
		if (body.length() == 0) {
			log("unsubscribe request from %s sent without group", to);
			return null;
		}
		String group = body;
		String text = null;
		if (!group.equals("*")) {
			Map<String, String> meta = getGroupMeta(group);
			if (meta == null) {
				log("unsubsribe attempted on group %s, not listed", group);
				return null;
			}
			String arn = meta.get("arn");
			if (arn == null) {
				throwException("meta data on group %s missing arn", group);
			}
			String who = to.equals(number) ? "You are" : number.concat(" is");

			if(unsubscribeFromTopic(arn, number)) {
				text = String.format("%s now unsubscribed from %s.", who, group);
			} else if (admin) {
				text = String.format("%s not part of %s.", who, group);
			}

		} else {
			String who = to.equals(number) ? "You are" : number.concat(" is");
			if(unsubscribeFromAllTopics(number)) {
				text = String.format("%s now unsubscribed from all groups.", who);
			} else if (admin) {
				text = String.format("%s not a part of any groups.", who, group);
			}
		}
		if(text != null) {
			return new Response(text);
		}
		return null;
	}

	private Response group(String to, String body) throws Exception {
		if (body == null) {
			return ayuda(to, "group");
		}
		// list is the only command that cannot run without
		// an argument.
		if (body.trim().toLowerCase().equals("list")) {
			return groupList(to, "");
		}
		String[] sp = body.split("\\s+", 2);
		if (sp.length < 2) {
			log("group command sent without any text");
			return ayuda(to, "group");
		}
		String cmd = sp[0].toLowerCase();
		String realBody = sp[1].trim();
		String[] sp2;
		switch(cmd){
		case "text":
			return groupText(to, realBody);
		case "code":
			return groupCode(to, realBody);
		case "subscribe":
			sp2 = realBody.split("\\s+", 2);
			if (sp2.length < 2) {
				log("subscribe request from %s sent without group", to);
			} else {
				String number = sp[0].replaceAll(NON_NUMERIC, "");
				String group = sp[1];
				return subscribe(to, number, group, true);
			}
			break;
		case "unsubscribe":
			sp2 = realBody.split("\\s+", 2);
			if (sp2.length < 2) {
				log("unsubscribe request from %s sent without group", to);
			} else {
				String number = sp[0].replaceAll(NON_NUMERIC, "");
				String group = sp[1];
				return unsubscribe(to, number, group, true);
			}
			break;
		case "create":
			return groupCreate(to, realBody);
		case "delete":
			return groupDelete(to, realBody);
		case "list":
			return groupList(to, realBody);
		default:
			return ayuda(to, "group");
		}
		return null;
	}

	private Response groupText(String to, String body) throws Exception {
		String[] sp = body.split("\\s+", 2);
		if (sp.length < 2) {
			return ayuda(to, "group text");
		}
		String groupName = sp[0].toLowerCase();
		String realBody = sp[1];
		boolean success = true;
		String who = null;
		if (!groupName.equals("*")) {
			Map<String, String> meta = null;
			try {
				meta = getGroupMeta(groupName);
			} catch (Exception e) {
				log(e.toString());
				meta = null;
			}
			if (meta == null) {
				log("group text command sent for non existent group %s", groupName);
				return new Response(to, String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
			}
			String arn = meta.get("arn");
			if (arn == null) {
				log("could not find group arn for group %s for a group text command", groupName);
				return new Response(String.format("It looks like the group %s exists, but it is malformed in the system, please call the administrator to fix it.", groupName));
			}
			try{
				textTopic(arn, realBody);
			} catch(Exception e) {
				log(e.toString());
				success = false;
			}
			who = String.format("group %s", groupName);
			
		} else {
			try{
				textAllTopics(realBody);
			} catch(Exception e) {
				log(e.toString());
				success = false;
			}
			who = "everyone";
		}
		if (!success) {
			return new Response(String.format("I'm sorry I ran into an error trying to send your text to %s. Please contact the administrator to fix it.", who));
		}
		return new Response(String.format("I sent your text to %s.", who));
	}


	private Response groupCode(String to, String body) throws Exception {
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
			return new Response(String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
		}
		String arn = meta.get("arn");
		if (arn == null) {
			log("could not find group arn for group %s for a group text command", groupName);
			return new Response(String.format("It looks like the group %s exists, but it is malformed in the system, please call the administrator/owner to fix it.", groupName));
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
			code = generateRandomCode();
			meta.put("code", code.toLowerCase());
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
			return new Response(String.format("There was an error setting the subscribe code for %s, try again in a few seconds. If the problem persists contact the administrator to fix the issue.", groupName));
		}
		return new Response(String.format("The subscribe code (for the next 15 minutes) for %s is \"%s\"", groupName, code));
	}

	private Response groupCreate(String to, String body) throws Exception {
		body = body.toLowerCase();
		if (!body.matches(ALPHA_NUMERIC)) {
			return ayuda(to, "group create");
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
		if (success) {
			try {
				HashMap map = new HashMap();
				map.put("arn", ctr.getTopicArn());
				setGroupMeta(groupName, map);
			} catch(Exception e) {
				log(e.toString());
				success = false;
			}
		}
		if (!success) {
			return new Response(String.format("There was an error creating the group %s. Contact the administrator to fix it.", groupName));
		}
		return new Response(String.format("Successfully created the group %s", groupName));
	}

	private Response groupDelete(String to, String body) throws Exception {
		body = body.toLowerCase();
		if (!body.matches(ALPHA_NUMERIC)) {
			return ayuda(to, "group delete");
		}
		String groupName = body;
		Map<String, String> meta = null;
		try {
			meta = getGroupMeta(groupName);
		} catch (Exception e) {
			log(e.toString());
			meta = null;
		}
		if (meta == null) {
			log("group delete command sent for non existent group %s", groupName);
			return new Response(String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
		}
		boolean success = true;
		try {
			SNSClient.deleteTopic(new DeleteTopicRequest(meta.get("arn")));
		} catch(Exception e) {
			log(e.toString());
			success = false;
		}
		if (success) {
			try {
				unsetGroup(groupName);
			} catch(Exception e) {
				log(e.toString());
				success = false;
			}
		}
		if (!success) {
			return new Response(String.format("There was an error deleting the group %s. Contact the administrator to fix it.", groupName));
		}
		return new Response(String.format("Successfully deleted the group %s", groupName));
	}

	private Response groupList(String to, String body) throws Exception {
		body = body.trim().toLowerCase();
		if (body.length()  == 0) {
			Collection<String> groupNames = null;
			try {
				groupNames = getAllGroupNames();
			} catch(Exception e) {
				log(e.toString());
				return new Response("Failed to get list of groups, please contact administrator.");
			}
			return new Response(String.join("\n", groupNames));
		}
		if (!body.matches(ALPHA_NUMERIC)) {
			return ayuda(to, "group list");
		}
		String groupName = body;
		Map<String, String> meta = null;
		try {
			meta = getGroupMeta(groupName);
		} catch (Exception e) {
			log(e.toString());
			meta = null;
		}
		if (meta == null) {
			log("group list command sent for non existent group %s", groupName);
			return new Response(String.format("I'm sorry, but I couldn't find a group called \"%s\"", groupName));
		}
		String sendBody;
		try {
			final StringBuilder sb = new StringBuilder();
			subscriptionsByTopic(meta.get("arn"), (Subscription sub) -> {
					sb.append(sub.getEndpoint());
					sb.append("\n");
					return true;
				});
			sendBody = sb.toString();
			
		} catch(Exception e) {
			log(e.toString());
			sendBody = String.format("There was an error retrieving the subscriptions in \"%s\". Contact the administrator to fix it.", groupName);
			
		}
		return new Response(sendBody);
	}

	private static boolean isAdmin(String number) throws Exception {
		final AtomicReference<Boolean> admin = new AtomicReference<Boolean>(new Boolean(false));
		subscriptionsByTopic(AdminARN, (Subscription sub) -> {
				if(sub.getEndpoint().replaceAll(NON_NUMERIC, "").equals(number)) {
					admin.set(new Boolean(true));
					return false;
				}	
				return true;
			});
		return admin.get().booleanValue();
	}

	private static boolean unsubscribeFromTopic(String number, String topicARN) throws Exception {
		final AtomicReference<String> subARN = new AtomicReference<String>(null);
		subscriptionsByTopic(topicARN, (Subscription sub) -> {
				if(sub.getEndpoint().replaceAll(NON_NUMERIC, "").equals(number)) {
					subARN.set(sub.getSubscriptionArn());
					return false;
				}
				return true;
			});
		String arn = subARN.get();
		if (arn != null) {
			SNSClient.unsubscribe(new UnsubscribeRequest(arn));
			return true;
		}
		return false;
	}

	private static boolean unsubscribeFromAllTopics(String number) throws Exception {
		final AtomicReference<Boolean> success = new AtomicReference<Boolean>(new Boolean(false));
		final AtomicReference<Boolean> exception = new AtomicReference<Boolean>(new Boolean(false));
		final StringBuilder sb = new StringBuilder();
		allSubscriptions((Subscription sub) -> {
				if(sub.getEndpoint().replaceAll(NON_NUMERIC, "").equals(number)) {
					String arn = sub.getSubscriptionArn();
					try {
						SNSClient.unsubscribe(new UnsubscribeRequest(arn));
					} catch(Exception e) {
						exception.set(new Boolean(true));
						sb.append(e.toString());
						return true;
					}
					success.set(true);
				}
				return true;
			});
		if (exception.get().booleanValue()) {
			throw new Exception(sb.toString());
		}
		return success.get().booleanValue();
	}


	private static void subscriptionsByTopic(String topicARN, SubscriptionOperator operator) throws Exception {
		ListSubscriptionsByTopicRequest tr = new ListSubscriptionsByTopicRequest();
		tr.setTopicArn(topicARN);
		ListSubscriptionsByTopicResult res = SNSClient.listSubscriptionsByTopic(tr);
		if(iterateOverSubscriptions(res.getSubscriptions(), operator)) {
			String nextToken = res.getNextToken();
			while(nextToken != null) {
				ListSubscriptionsByTopicRequest tr2 = new ListSubscriptionsByTopicRequest();
				tr2.setTopicArn(topicARN);
				tr2.setNextToken(nextToken);
				ListSubscriptionsByTopicResult resN = SNSClient.listSubscriptionsByTopic(tr2);
				if(iterateOverSubscriptions(resN.getSubscriptions(), operator)) {
					nextToken = resN.getNextToken();
				} else {
					nextToken = null;
				}
			}
		}

	}

	private static void allSubscriptions(SubscriptionOperator operator) throws Exception {
		ListSubscriptionsResult res = SNSClient.listSubscriptions();
		if(iterateOverSubscriptions(res.getSubscriptions(), operator)) {
			String nextToken = res.getNextToken();
			while(nextToken != null) {
				ListSubscriptionsRequest sr = new ListSubscriptionsRequest();
				sr.setNextToken(nextToken);
				ListSubscriptionsResult resN = SNSClient.listSubscriptions(sr);
				if(iterateOverSubscriptions(resN.getSubscriptions(), operator)) {
					nextToken = resN.getNextToken();
				} else {
					nextToken = null;
				}
			}
		}

	}

	private static boolean textAllTopics(String text) throws Exception {
		ListTopicsResult res = SNSClient.listTopics();
		List<Topic> topics = res.getTopics();
		String nextToken = res.getNextToken();
		while(nextToken != null) {
			ListTopicsRequest tr = new ListTopicsRequest();
			tr.setNextToken(nextToken);
			ListTopicsResult resN = SNSClient.listTopics(tr);
			topics.addAll(resN.getTopics());
			nextToken = resN.getNextToken();
		}
		boolean success = true;
		StringBuilder sb = new StringBuilder();
		for(Topic topic : topics) {
			String arn = topic.getTopicArn();
			try{
				textTopic(arn, text);
			} catch(Exception e) {
				sb.append(e.toString());
				success = false;
			}
		}
		return success;
	}

	private static Collection<String> getAllGroupNames() throws Exception {
		ListTagsRequest ltr = new ListTagsRequest();
		ltr.setResource(LambdaARN);
		ListTagsResult res = LambdaClient.listTags(ltr);
		return res.getTags().keySet();
	}

	private static void textTopic(String topicARN, String text) throws Exception {
		SNSClient.publish(new PublishRequest(topicARN, text));
	}

	private static boolean iterateOverSubscriptions(List<Subscription> subs, SubscriptionOperator operator) throws Exception {
		for(Subscription sub : subs) {
			if(!operator.op(sub)) {
				return false;
			}
		}
		return true;
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

	private static void unsetGroup(String group) throws Exception {
		UntagResourceRequest urr = new UntagResourceRequest();
		urr.setResource(LambdaARN);
		List<String> keys = new ArrayList<String>();
		keys.add(group);
		urr.setTagKeys(keys);
		LambdaClient.untagResource(urr);
	}
	

	private static String encodeJSONTag(String json) throws Exception {
		return new String(Base64.getEncoder().encode(json.getBytes()), "UTF-8");
	}

	private static JSONObject decodeJSONTag(String json) throws Exception {
		String s = new String(Base64.getDecoder().decode(json.getBytes()), "UTF-8");
		JSONParser parser = new JSONParser();
		return (JSONObject)parser.parse(s);
	}

	private static String generateRandomCode() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i <= 3; i++){
			sb.append(RANDOM_CHARS[ThreadLocalRandom.current().nextInt(0, RANDOM_CHARS.length)]);
		}
		return sb.toString();
	}
}
