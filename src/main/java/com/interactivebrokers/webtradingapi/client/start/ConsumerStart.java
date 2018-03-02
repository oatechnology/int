package com.interactivebrokers.webtradingapi.client.start;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.interactivebrokers.webtradingapi.client.http.HttpConsumerClient;
import com.interactivebrokers.webtradingapi.client.model.Message;
import com.interactivebrokers.webtradingapi.client.oauth.OAuthMessenger;
import com.interactivebrokers.webtradingapi.client.oauth.SecuredRequest;

public class ConsumerStart {

    private static final int EXIT_FAILED = 1;
    private static final Options options = new Options();
    private final static Logger logger = LoggerFactory.getLogger(ConsumerStart.class);
    private final static String defaultRealmName = "limited_poa";
    private final static String defaultLiveHostUrl = "https://www.interactivebrokers.com/tradingapi/v1/";
    private final static String defaultPaperHostUrl = "https://www.interactivebrokers.com/ptradingapi/v1/";
    private final static String defaultOauthHostUrl = "https://www.interactivebrokers.com/iblink.proxy/v1";

    public  Message getLiveSessionToken( String username , String password) throws Exception {
    	String[] args = null; // need to delete
        initCmdLineOptions();

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (UnrecognizedOptionException e) {
            logger.error("unrecognized option: {}", e.getMessage());
            printHelp();
        } catch (Exception e) {
            printHelp();
        }

        if (cmd == null || cmd.hasOption("h")) {
            printHelp();
            return null;
        }

        final String file = "etc/consumer/consumer.json";//cmd.getOptionValue("consumer", "");
        if (file.isEmpty()) {
            failed("consumer file required, see --consumer option");
        }

        final String loginMode = cmd.getOptionValue("loginMode", "live");
        final String host = cmd.getOptionValue("host", "paper".equals(loginMode)
                ? defaultPaperHostUrl : defaultLiveHostUrl);
        final String oauthHost = cmd.getOptionValue("oauthHost", defaultOauthHostUrl);
        final ThirdPartyConsumer consumer = new ThirdPartyConsumer(file);

        final String resource ="etc/requests/marketdata.json";// cmd.getOptionValue("resource");
     //   final String username = cmd.getOptionValue("username");
     //   final String password = cmd.getOptionValue("password");

        if (resource == null || resource.isEmpty()) {
            logger.error("specify a protected resource with --resource");
            return null;
        }

        if (username == null || username.isEmpty()) {
            logger.error("specify a username with --username");
            return null;
        }

        if (password == null || password.isEmpty()) {
            logger.error("specify a password with --password");
            return null;
        }

        final SecuredRequest protectedRequest = SecuredRequest.load(resource);

        final HttpConsumerClient client = new HttpConsumerClient(consumer, host, oauthHost);
        client.setDebugHttp(cmd.hasOption("print-http"));

        final Pair<String, String> vals = OAuthMessenger.obtainAccessToken(client, username, password, loginMode);
        logger.debug("----------------------------------------------------------------------------------");

        if (vals == null) {
            logger.error("Aborting full run, null token/secret");
            return null;
        }

        final String accessToken = vals.getKey();
        final String encryptedSecret = vals.getValue();

        logger.info("Sleeping 0.5 seconds to allow access token propagation");
        Thread.sleep(500);
        final byte[] lst = OAuthMessenger.getLiveSessionToken(client, accessToken, encryptedSecret);
        logger.debug("----------------------------------------------------------------------------------");

        if (lst == null) {
            logger.error("aborting full run, null live session token");
        return null;
        }else {
            logger.info("Sleeping 0.5 seconds to allow live session token propagation");
            Thread.sleep(500);
            client.sendProtectedResourceRequest(accessToken, lst, protectedRequest);
            
            return new Message(lst, accessToken);
        }
 
    }

    private static void failed(String err, Object... args) {
        logger.error(err, args);
        System.exit(EXIT_FAILED);
    }

    @SuppressWarnings("static-access")
    private static void initCmdLineOptions() {
        options.addOption("h", "help", false, "print this message");
        options.addOption(null, "consumer", true, "path to consumer.json file");
        options.addOption(null, "username", true, "username for http authentication");
        options.addOption(null, "password", true, "password for http authentication");
        options.addOption(null, "resource", true, "description of the http request to be made in json format");
        options.addOption(null, "print-http", false, "print outgoing http request to the stdout");
        options.addOption(null, "loginMode", true, "use --loginMode paper to specify a paper-trading login");
        options.addOption(null, "host", true, "base url of the webapi (default " + defaultPaperHostUrl + ")");
        options.addOption(null, "oauthHost", true, "base url of the oauth host (default " + defaultOauthHostUrl + ")");
    }

    private static void printHelp() {
        HelpFormatter help = new HelpFormatter();
        help.printHelp("java -jar RunCli or java -cp .jar " + ConsumerStart.class.getSimpleName(), options);
        System.exit(EXIT_FAILED);
    }

}
