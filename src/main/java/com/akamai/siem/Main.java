package com.akamai.siem;

import com.akamai.edgegrid.signer.ClientCredential;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridInterceptor;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridRoutePlanner;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.splunk.*;
import com.splunk.modularinput.*;
import com.splunk.modularinput.Argument.DataType;
import com.splunk.modularinput.Event;
import com.splunk.modularinput.Scheme.StreamingMode;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.xml.stream.XMLStreamException;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import static com.splunk.modularinput.EventWriter.*;
import static java.lang.String.format;
import static java.lang.String.join;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.math.NumberUtils.isDigits;


// All modular inputs should inherit from the abstract base class com.splunk.modularinput.Script. They must override
// the getScheme and streamEvents methods, and, if the scheme returned by getScheme had
// Scheme.setUseExternalValidation(true) called on it, the validateInput method. The user must provide a main
// method since static methods can't be inherited in Java. However, the main is very simple.
public class Main extends Script {

    // Jackson to convert JSON to String and vice versa
    public static ObjectMapper mapper;
    public static String staticOffset = "";

    // BlockingQueue is a java Queue that support operations that wait for the queue to become non-empty
    // when retrieving and removing an element, and wait for space to become available in the queue when adding an element.
    // They are thread safe
    // put(E e): This method is used to insert elements to the queue. If the queue is full, it waits for the space to be available.
    // E take(): This method retrieves and remove the element from the head of the queue. If queue is empty it waits for the element to be available.
    BlockingQueue<String> queue = new LinkedBlockingQueue<String>(1024 * 256);
    BlockingQueue<Event> eventQueue = new LinkedBlockingDeque<Event>(1024 * 512);

    private static String _MASK_ = "<hidden>";
    private static String _AKAMAI_API_PARAM_OFFSET_BASED_ = "?offset=%s";
    private static String _AKAMAI_API_PARAM_TIME_BASED_ = "?from=%s";
    private static String _AKAMAI_API_PARAM_TIME_TO_BASED_ = "&to=%s";
    private static String _AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_ = "?to=%s";
    private static String _AKAMAI_API_PARAM_LIMIT_BASED = "&limit=%s";
    private static String _AKAMAI_API_SECURITY_CONFIG_DELIMITER_ = ";";
    private static Integer _AKAMAI_API_MAX_LIMIT_ = 600000;
    private static Integer _AKAMAI_API_DEFAULT_LIMIT_ = 150000;
    private static Integer _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ = 5;
    private static double realTime = 0;

    private static final Map<String, Integer> logLevel;

    private static final String EMPTY = "";

    static {
        HashMap<String, Integer> mylogLevel = new HashMap<String, Integer>();
        mylogLevel.put(EventWriter.DEBUG, 0);
        mylogLevel.put(EventWriter.INFO, 1);
        mylogLevel.put(EventWriter.WARN, 2);
        mylogLevel.put(EventWriter.ERROR, 3);
        mylogLevel.put(EventWriter.FATAL, 4);

        logLevel = Collections.unmodifiableMap(mylogLevel);
        mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    // Start of the program (Splunk defined standard)
    // new modular input script
    public static void main(String[] args) throws Exception {
        new Main().run(args);
    }

    // Create scheme (data input) and set initial configuration
    @Override
    public Scheme getScheme() {

        Scheme scheme = new Scheme("AKAMAI SIEM API");
        scheme.setDescription("Security Information and Event Management");

        // Perform validation logic. Override the validateInput method if this is true
        scheme.setUseExternalValidation(true);

        // Specifies whether this modular input kind will send events to Splunk as XML
        // (the default and preferred value) or plain text.
        scheme.setStreamingMode(StreamingMode.XML);

    /*
        setUseSingleInstance(true) - the scheme will pass all the instances of the modular input
        to a single instance of the script.
        Otherwise, Splunk Enterprise starts a Java Virtual Machine (JVM)
        for each instance of the input.
     */
        scheme.setUseSingleInstance(false);

        createSchemeArgument(scheme, "hostname", EMPTY, true, true, DataType.STRING);
        createSchemeArgument(scheme, "security_configuration_id_s_", "[semicolon delimited]", true, true, DataType.STRING);
        createSchemeArgument(scheme, "client_token", EMPTY, true, true, DataType.STRING);
        createSchemeArgument(scheme, "client_secret", EMPTY, true, true, DataType.STRING);
        createSchemeArgument(scheme, "access_token", EMPTY, true, true, DataType.STRING);
        createSchemeArgument(scheme, "initial_epoch_time", EMPTY, false, false, DataType.NUMBER);
        createSchemeArgument(scheme, "final_epoch_time", EMPTY, false, false, DataType.NUMBER);
        createSchemeArgument(scheme, "limit", EMPTY, false, false, DataType.NUMBER);
        createSchemeArgument(scheme, "log_level", "DEBUG, INFO, WARN, ERROR, FATAL", false, false, DataType.STRING);
        createSchemeArgument(scheme, "proxy_host", EMPTY, false, false, DataType.STRING);
        createSchemeArgument(scheme, "proxy_port", EMPTY, false, false, DataType.NUMBER);

        return (scheme);
    }

    @Override
    public void validateInput(final ValidationDefinition definition, final EventWriter ew) throws Exception {
        String methodName = "validateInput";
        try {
            // Sets the SSL security protocol of this service.
            HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

            // The EventWriter class encapsulates writing events and error messages to Splunk from a modular input.
            // synchronizedLog(severity, errorMessage)
            ew.synchronizedLog(INFO, format("In %s, begin validate input", methodName));
            ew.synchronizedLog(INFO, format("In %s, stanza name = %s", methodName, definition.getName()));

            // Get log level from all input values provided by us as string (client_Secret, access_token etc.)
            String log_level = getInputValueAsString(definition, "log_level");
            ew.synchronizedLog(INFO, format("In %s, log_level=%s", methodName, log_level));

            // Gets a session key providing access to splunkd's REST API on this host.
            String session_key = definition.getSessionKey();

            String hostname = getInputValueAsString(definition, "hostname");

            // Add https in the hostname
            if ((hostname != null) && !hostname.isEmpty()) {
                hostname = "https://" + hostname;
            }

            String security_configuration_id_s_ = getInputValueAsString(definition, "security_configuration_id_s_");
            String client_token = getInputValueAsString(definition, "client_token");
            String client_secret = getInputValueAsString(definition, "client_secret");
            String access_token = getInputValueAsString(definition, "access_token");
            String initial_epoch_time = getInputValueAsString(definition, "initial_epoch_time");
            debug(ew, log_level, format("initial_epoch_time=%s", initial_epoch_time));
            String final_epoch_time = getInputValueAsString(definition, "final_epoch_time");
            debug(ew, log_level, format("final_epoch_time=%s", final_epoch_time));
            String limit = getInputValueAsString(definition, "limit");
            debug(ew, log_level, format("limit=%s", limit));
            String proxy_host = getInputValueAsString(definition, "proxy_host");
            String proxy_port = getInputValueAsString(definition, "proxy_port");
            debug(ew, log_level, "Begin Log Level validation");

            List<String> errors = new ArrayList<String>();

            if (!isValidLogLevel(log_level)) {
                errors.add(format("%s is not a valid Log Level", log_level));
                log_level = EventWriter.INFO;
            }
            debug(ew, log_level, "Log Level validation complete");

            debug(ew, log_level, "Begin Hostname validation");
            if (!isValidHostName(hostname)) {
                errors.add(format("%s is an invalid Hostname", hostname));
            }
            debug(ew, log_level, "Hostname validation complete");

            debug(ew, log_level, "Begin Security Configuration ID(s) validation");
            validateSecurityConfigIds(security_configuration_id_s_, errors);
            debug(ew, log_level, "Security Configuration ID(s) validation complete");

            debug(ew, log_level, "Begin Client Token validation");
            if (isEmpty(client_token)) {
                errors.add("Please specify a valid Client Token");
            }
            debug(ew, log_level, "Client Token validation complete");

            debug(ew, log_level, "Begin Client Secret validation");
            if (isEmpty(client_secret)) {
                errors.add("Please specify a valid Client Secret");
            } else {
                logMessage(ew, EventWriter.INFO, log_level, format("In %s, Service connect to TA-Akamai_SIEM app ", methodName));

                // Get service for Akamai's app
                // The Service class represents a Splunk service instance at a given address (host:port),
                // accessed using the http or https protocol scheme.
                // TODO: How do we provide TA-Akamai_SIEM?
                Service akamaiSplunkService = getServiceForApp(session_key, "TA-Akamai_SIEM");

                debug(ew, log_level, "get password service...");

                // Returns a collection of passwords. This collection is used for managing secure credentials.
                PasswordCollection passwordCollection = akamaiSplunkService.getPasswords();
                debug(ew, log_level, "construct stanza...");

                // Get client_Secret, client_toke and access_token
                String clearClientSecret = readClearPassword(definition.getName(), "client_secret", passwordCollection);
                String clearClientToken = readClearPassword(definition.getName(), "client_token", passwordCollection);
                String clearAccessToken = readClearPassword(definition.getName(), "access_token", passwordCollection);

                if (_MASK_.equalsIgnoreCase(client_secret)) {
                    if (isEmpty(clearClientSecret)) {
                        errors.add("Please specify a valid Client Secret");
                    }
                }

                if (_MASK_.equalsIgnoreCase(client_token)) {
                    if (isEmpty(clearClientToken)) {
                        errors.add("Please specify a valid Client Token");
                    }
                }

                if (_MASK_.equalsIgnoreCase(access_token)) {
                    if (isEmpty(clearAccessToken)) {
                        errors.add("Please specify a valid Access Token");
                    }
                }
                debug(ew, log_level, "password validation complete");
            }
            debug(ew, log_level, "Client Secret validation complete");

            debug(ew, log_level, "Begin Access Token validation");
            if (isEmpty(access_token)) {
                errors.add("Please specify a valid Access Token");
            }
            debug(ew, log_level, "Access Token validation complete ");

            debug(ew, log_level, "Begin Initial Epoch Time validation");
            validateEpochTime(initial_epoch_time, errors);
            debug(ew, log_level, "Initial Epoch Time validation complete ");

            debug(ew, log_level, "Begin Final Epoch Time validation");
            validateEpochTime(final_epoch_time, errors);
            debug(ew, log_level, "Final Epoch Time validation complete");

            // Initial Epoch time is null or empty but final is not
            if (isEmpty(initial_epoch_time) && !isEmpty(final_epoch_time)) {
                errors.add(format("Initial Epoch Time must be specified"));
            }

            // final > initial
            if (!isEmpty(initial_epoch_time) && !isEmpty(final_epoch_time)) {
                long start = Long.valueOf(initial_epoch_time);
                long end = Long.valueOf(initial_epoch_time);
                if (end < start) {
                    errors.add(format("Final Epoch Time must be gearter than Initial Epoch Time"));
                }
            }

            debug(ew, log_level, "Begin Limit validation");
            if (!isEmpty(limit)) {
                if (isDigits(limit)) {
                    Integer value = Integer.valueOf(limit);
                    if (value <= 0 || value > _AKAMAI_API_MAX_LIMIT_) {
                        errors.add(format("%s is not valid Limit", limit));
                    }
                } else {
                    errors.add(format("%s is not valid Limit", limit));
                }
            }
            debug(ew, log_level, "Limit validation complete");

            debug(ew, log_level, "Begin Proxy Host/Port validation");
            if (!isEmpty(proxy_host)) {
                if (isValidHostName(proxy_host)) {
                    errors.add(format("%s is an invalid Proxy Host", proxy_host));
                }

                if (!isEmpty(proxy_port)) {
                    if (isDigits(proxy_port)) {
                        Integer value = Integer.valueOf(proxy_port);

                        if (value <= 0) {
                            errors.add(format("%s is not valid Proxy Port", proxy_port));
                        }
                    } else {
                        errors.add(format("%s is not valid Proxy Port", proxy_port));
                    }
                }
            }
            debug(ew, log_level, "Proxy Host/port validation complete");

            if (errors.size() > 0) {
                String formattedErrors = join(",", errors);
                ew.synchronizedLog(EventWriter.INFO, format("infoMsg= In %s, found errors : %s", methodName, formattedErrors));
                throw new InputException(formattedErrors);
            }
            debug(ew, log_level, "Error Checking complete");
            info(ew, log_level, "done validation");
        } catch (InputException iex) {
            logException(ew, iex);
            throw (iex);
        } catch (Exception ex) {
            logException(ew, ex);
            throw (ex);
        }
    }


    // The InputDefinition class encodes the XML defining inputs
    // that Splunk passes to a modular input script as a Java object
    @Override
    public void streamEvents(InputDefinition inputDefinition, EventWriter ew)
            throws MalformedDataException, XMLStreamException, IOException {

        String methodName = "streamEvents";

        try {
            ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, begin streamEvents", methodName));

            HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

            Map<String, Map<String, Parameter>> inputs = inputDefinition.getInputs();

            for (String inputName : inputs.keySet()) {

                final long start = System.nanoTime();

                // Get nummber of core in the systems
                Integer coreCnt = Runtime.getRuntime().availableProcessors() - 1;

                // create coreCnt number of executor threads
                ExecutorService consumerExecutorService = Executors.newFixedThreadPool(coreCnt);
                ArrayList<Future<Double>> consumerFutures = new ArrayList<Future<Double>>();

                // create an event executor thread
                ExecutorService eventExecutorService = Executors.newFixedThreadPool(1);

                ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, inputName=%s", methodName, inputName));
                ew.synchronizedLog(EventWriter.INFO,
                        format("infoMsg = %s, inputName(String)=%s", methodName, inputName.toString()));

                String log_level = getInputValueAsString(inputs.get(inputName), "log_level");

                if (log_level != null) {
                    log_level = log_level.toUpperCase();
                    if (!logLevel.containsKey(log_level)) {
                        ew.synchronizedLog(EventWriter.INFO,
                                "infoMsg=Errors while processing Log Level. Please check instance stanza configuration. Defaulting to INFO");
                        log_level = INFO;
                    }
                } else {
                    log_level = INFO;
                }

                debug(ew, log_level, format("log_level=%s", log_level));

                String hostname = getInputValueAsString(inputs.get(inputName), "hostname");
                String configIds = getInputValueAsString(inputs.get(inputName), "security_configuration_id_s_");
                String client_token = getInputValueAsString(inputs.get(inputName), "client_token");
                String access_token = getInputValueAsString(inputs.get(inputName), "access_token");
                String initial_epoch_time = getInputValueAsString(inputs.get(inputName), "initial_epoch_time");
                debug(ew, log_level, format("initial_epoch_time=%s", initial_epoch_time));
                String final_epoch_time = getInputValueAsString(inputs.get(inputName), "final_epoch_time");
                debug(ew, log_level, format("final_epoch_time=%s", final_epoch_time));
                String limit = getInputValueAsString(inputs.get(inputName), "limit");
                debug(ew, log_level, format("limit=%s", limit));
                String interval = getInputValueAsString(inputs.get(inputName), "interval");
                String proxy_host = getInputValueAsString(inputs.get(inputName), "proxy_host");
                String proxy_scheme = null;

                if (!isEmpty(proxy_host)) {
                    String lc_proxy_host = proxy_host.toLowerCase();
                    if (lc_proxy_host.startsWith("https://")) {
                        proxy_scheme = "https";
                        proxy_host = lc_proxy_host.replace("https://", "");
                    } else if (lc_proxy_host.startsWith("http://") == true) {
                        proxy_scheme = "http";
                        proxy_host = lc_proxy_host.replace("http://", "");
                    }
                }
                String proxy_port_string = getInputValueAsString(inputs.get(inputName), "proxy_port");
                Integer proxy_port = null;
                if (!isEmpty(proxy_port_string)) {
                    proxy_port = Integer.valueOf(proxy_port_string);
                }
                String client_secret = getInputValueAsString(inputs.get(inputName), "client_secret");
                String clearClientSecret = client_secret;
                String clearClientToken = client_token;
                String clearAccessToken = access_token;
                String sessionKey = inputDefinition.getSessionKey();

                // If client secret is masked
                if (_MASK_.equalsIgnoreCase(client_secret) == true) {

                    info(ew, log_level, format("infoMsg %s Service connect to Akamai_SIEM App...", methodName));
                    Service akamaiSplunkService = getServiceForApp(sessionKey, "TA-Akamai_SIEM");
                    PasswordCollection passwordCollection = akamaiSplunkService.getPasswords();
                    String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");

                    clearClientSecret = readClearPassword(inputStanza, "client_secret", passwordCollection);
                    clearClientToken = readClearPassword(inputStanza, "client_token", passwordCollection);
                    if (isEmpty(clearClientToken)) {
                        clearClientToken = client_token;
                    }
                    clearAccessToken = readClearPassword(inputStanza, "access_token", passwordCollection);
                    if (isEmpty(clearAccessToken)) {
                        clearAccessToken = access_token;
                    }
                }

                if (_MASK_.equals(clearClientSecret)) {
                    error(ew, log_level, format("clearClientSecret(Wrong Credentials)=%s", clearClientSecret));
                    throw new InputException("Client Secret in password store is masked.");
                }

                info(ew, log_level, format("infoMsg=Processing Data..."));


                String offset = null;
                Integer error_count = 0;

                // Get offset, error count etc. from the kv store
                Service kvStoreService = getServiceForApp(sessionKey, "kvstore");
                stanza_state kvStoreStanza = getValuesFromKVStore(ew, log_level, kvStoreService, inputName);

                // Get offset from the kvstore value
                if (kvStoreStanza != null) {
                    offset = kvStoreStanza.offset;
                    Main.staticOffset = kvStoreStanza.offset;
                }

                // Based on the given values of time, offset and limit, build the OPEN API URL
                String queryString = processQueryString(initial_epoch_time, final_epoch_time, offset, limit);
                String urlToRequest = "https://" + hostname + "/siem/v1/configs/" + configIds + queryString;
                info(ew, log_level, format("urlToRequest=%s", urlToRequest));

                // EdgeGrid is Akamai's API authentication method
                // To request Akamai APIs, you’ll need to properly authenticate your requests
                final long startEdgeGrid = System.nanoTime();

                // Build client credentials using Akamai OPEN API credential builder
                ClientCredential credential = ClientCredential.builder().accessToken(clearAccessToken)
                        .clientToken(clearClientToken).clientSecret(clearClientSecret).host(hostname).build();

                // Build Httpclient using apache
                HttpClient client =
                        HttpClientBuilder.create().addInterceptorFirst(new ApacheHttpClientEdgeGridInterceptor(credential))
                                .setRoutePlanner(new ApacheHttpClientEdgeGridRoutePlanner(credential)).build();
                HttpGet request = new HttpGet(urlToRequest);

                // Set proxy for the Http GET request
                if ((proxy_host != null) && (proxy_host.isEmpty() == false)) {
                    HttpHost proxy = new HttpHost(proxy_host, proxy_port, proxy_scheme);
                    RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
                    request.setConfig(config);
                }

                try {
                    // Make the OPEN API call and get the response
                    HttpResponse response = client.execute(request);
                    int statusCode = response.getStatusLine().getStatusCode();
                    info(ew, log_level, format("status code=%s", statusCode));

                    if (statusCode == HttpStatus.SC_OK) {

                        // Assign coreCnt number of asynchronous tasks to consumer service
                        // get the Future handle to track the response of the service
                        for (int i = 0; i < coreCnt; i++) {
                            // assign a task to the each thread
                            // It can submit a Callable or a Runnable task to an ExecutorService
                            // Depends on what kind of consumer task we sumbit

                            // returns Future
                            // Future allows us to get the result of a task's execution or to check the task's status
                            // Future , represents the result of an asynchronous computation
                            // When the asynchronous task is created, a Java Future object is returned
                            // This Future object functions as a handle to the result of the asynchronous task.
                            // Submits a value-returning "callable" task for execution and returns a
                            // Future representing the pending results of the task. The
                            // Future's {@code get} method will return the task's result upon successful completion.
                            // queue: Data to be processed
                            // eventQueue: Processed data
                            Future<Double> futureDbl = consumerExecutorService.submit(new Consumer(queue, eventQueue, inputName, ew, i));
                            consumerFutures.add(futureDbl);
                        }

                        // Submits a "runnable" task
                        // Runnable: doesn't return any value
                        eventExecutorService.submit(new EventConsumer(eventQueue, ew));

                        // Get the stream of response events from the OPEN API call
                        InputStream instream = response.getEntity().getContent();

                        // Time to retrieve data from LLDQ
                        double runningEdgeGridTime = System.nanoTime() - startEdgeGrid;

                        final long consumerStart = System.nanoTime();
                        long numRecords = 0l;

                        // Read the response
                        try (BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(instream))) {

                            String line;
                            Boolean running = true;

                            // Put response in the queue one line at a time till there is no more events
                            while (running) {
                                long readLineStart = System.nanoTime();

                                // Read the response line by line
                                line = bufferedreader.readLine();

                                // Time to read one line
                                runningEdgeGridTime += System.nanoTime() - readLineStart;

                                // Put response data and put it in the BlockingQueue
                                if (line != null) {
                                    numRecords++;
                                    queue.put(line);
                                } else {
                                    running = false;
                                }
                            }

                            // Poison Pill is a known message structure that ends the message exchange
                            // If there are 8 cores, put poisonPill 8 times in the queue
                            for (int i = 0; i < coreCnt; i++) {
                                queue.put("poisonPill");
                            }

                            info(ew, log_level, String.format("awaiting shutdown..."));

                            // shut down after all running threads finish their current work:
                            consumerExecutorService.shutdown();

                            try {
                                consumerExecutorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                            } catch (InterruptedException e) {

                            }

                            // Time to read the events from the InputStreamReader
                            double consumerRealTime = System.nanoTime() - consumerStart;

                            // Total time taken for all the tasks
                            Double cpuTime = 0.0;
                            for (Future<Double> future : consumerFutures) {
                                cpuTime += future.get();
                            }

                            // Splunk event
                            // TODO: What is the use of this code block?
                            // Poison Pill is a known message structure that ends the message exchange
                            Event poisonPill = new Event();
                            poisonPill.setSourceType("poisonPill");
                            eventQueue.put(poisonPill);
                            eventExecutorService.shutdown();
                            try {
                                eventExecutorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                            } catch (InterruptedException e) {

                            }

                            info(ew, log_level, String.format("termination complete....\n"));

                            // Total time from end to end
                            realTime = System.nanoTime() - start;
                            final int cores = Runtime.getRuntime().availableProcessors();

                            info(ew, log_level, String.format("                   Cores: %d\n", cores));
                            info(ew, log_level, String.format("       Consumer CPU time: %.2f s\n", cpuTime / SECONDS.toNanos(1)));
                            info(ew, log_level,
                                    String.format("           EdgeGrid time: %.2f s\n", runningEdgeGridTime / SECONDS.toNanos(1)));
                            info(ew, log_level, String.format("               Real time: %.2f s\n", realTime / SECONDS.toNanos(1)));
                            info(ew, log_level,
                                    String.format("Consumer CPU utilization: %.2f%%\n", 100.0 * cpuTime / consumerRealTime / coreCnt));
                            info(ew, log_level, String.format("         Lines Processed: %d\n\n", numRecords));

                        } catch (IOException ioe) {
                            throw ioe;
                        }

                    } else {
                        // Not 200 response
                        String responseData = EntityUtils.toString(response.getEntity());
                        error(ew, log_level, format("status code=%s", statusCode));
                        logAkamaiSIEMServiceFailure(ew, log_level, request, responseData, urlToRequest);

                        Event event = new Event();
                        event.setStanza(inputName);
                        event.setData(responseData);
                        ew.writeEvent(event);

                        error_count++;
                    }
                } catch (IOException ioe) {
                    logException(ew, ioe);
                    throw ioe;
                } finally {
                    kvStoreService = getServiceForApp(sessionKey, "kvstore");
                    try {
                        updateValuesInKVStore(ew, log_level, kvStoreService, inputName, staticOffset, error_count);
                    } catch (InputException e) {
                        logException(ew, e);
                    }

                    if (consumerExecutorService != null) {
                        consumerExecutorService.shutdownNow();
                    }
                    if (eventExecutorService != null) {
                        eventExecutorService.shutdownNow();
                    }
                }

                double intervalInSeconds = Double.parseDouble(interval);
                double realTimeInSeconds = realTime / SECONDS.toNanos(1);

                if ((!(_MASK_.equals(client_secret) && _MASK_.equals(access_token) && _MASK_.equals(client_token)))
                        || (realTimeInSeconds >= intervalInSeconds)) {
                    MyRunnable myRunnable = new MyRunnable(sessionKey, log_level, inputName, _MASK_, realTime, ew);
                    Thread t = new Thread(myRunnable);
                    t.start();
                }

            }
        } catch (Exception ex) {
            logException(ew, ex);
        }

        ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, end streamEvents", methodName));
    }

    // Get actual info from the data input configuration (client secret, access token etc.)
    private String readClearPassword(String inputStanza, String username, final PasswordCollection passwordCollection) {
        String keyWithReamlm = format("%s:%s:", inputStanza, username);

        if (passwordCollection.containsKey(keyWithReamlm)) {
            Password p = passwordCollection.get(keyWithReamlm);
            return p.getClearPassword();
        }
        return null;
    }

    // Set individual data input scheme (client_token, access_token etc.)
    private void createSchemeArgument(final Scheme scheme, final String argName, final String argDesc,
                                      final boolean requiredOnCreate, final boolean requiredOnedit, final DataType dataType) {
        Argument argument = new Argument(argName);
        argument.setName(argName);
        argument.setDescription(argDesc == null ? "" : argDesc);
        argument.setRequiredOnCreate(requiredOnCreate);
        argument.setRequiredOnEdit(requiredOnedit);
        argument.setDataType(dataType);
        scheme.addArgument(argument);
    }

    public String decode(String value) throws Exception {
        return new String(Base64.decodeBase64(value), StandardCharsets.UTF_8);
    }

    // DONE: Based on the given values of time, offset and limit, build the OPEN API URL
    public static String processQueryString(String initialEpochTime, String finalEpochTime, String offset, String limit) {

        String retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);

        if (!isEmpty(finalEpochTime)) {
            if (!isEmpty(initialEpochTime)) {
                retVal = format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
                retVal = retVal + format(_AKAMAI_API_PARAM_TIME_TO_BASED_, finalEpochTime);
            } else {
                retVal = format(_AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_, finalEpochTime);
            }

            if (!isEmpty(limit)) {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            } else {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }

        } else if (!isEmpty(initialEpochTime)) {
            if (isEmpty(offset)) {
                retVal = format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
            } else {
                retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
            }

            if (!isEmpty(limit)) {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            } else {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }

        } else {
            if (isEmpty(offset)) {
                retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, "NULL");
            } else {
                retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
            }

            if (!isEmpty(limit)) {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            } else {
                retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }
        }

        return (retVal);

    }

    // Get the value from the Splunk data input
    private String getInputValueAsString(final ValidationDefinition definition, final String paramName) {
        Parameter parameter = definition.getParameters().get(paramName);
        if (parameter != null) {
            return ((SingleValueParameter) parameter).getValue();
        }
        return null;
    }

    // Check if the log level is enabled
    public boolean isLogEnabled(final String log_level, final String log_threshold) {
        if (logLevel.containsKey(log_threshold)) {
            int ilogLevel = logLevel.get(log_level);
            int ilogThreshold = logLevel.get(log_threshold);
            if (ilogLevel >= ilogThreshold) {
                return true;
            }
        }
        return false;
    }

    // DONE: Log exception messages
    public static void logException(final EventWriter ew, final Exception ex) {
        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            ex.printStackTrace(pw);
            pw.flush();
            ew.synchronizedLog(EventWriter.ERROR, format("Message : %s, Exception : %s", ex.getMessage(), sw.toString()));
        }
    }

    // // DONE: Write DEBUG level log message
    private void debug(final EventWriter ew, final String log_threshold, final String message) {
        if (isLogEnabled(DEBUG, log_threshold)) {
            info(ew, log_threshold, message);
        }
    }

    // DONE: Write ERROR level log message
    private void error(final EventWriter ew, final String log_threshold, final String message) {
        logMessage(ew, ERROR, log_threshold, message);
    }

    // DONE: Write WARN level log message
    private void warn(final EventWriter ew, final String log_threshold, final String message) {
        logMessage(ew, WARN, log_threshold, message);
    }

    // DONE: Write INFO level log message
    private void info(final EventWriter ew, final String log_threshold, final String message) {
        logMessage(ew, INFO, log_threshold, message);
    }

    // DONE: Write log message using Splunk
    private void logMessage(final EventWriter ew, final String log_level, final String log_threshold,
                            final String message) {
        if (isLogEnabled(log_level, log_threshold)) {
            ew.synchronizedLog(log_level, message);
        }
    }

    // DONE: Validate the log level hashmap
    private boolean isValidLogLevel(final String inputLogLevel) {
        if (inputLogLevel != null) {
            return logLevel.keySet().contains(inputLogLevel);
        } else {
            return false;
        }
    }

    // DONE: Validate host name
    private boolean isValidHostName(final String hostname) {
        String[] schemes = {"http", "https"};
        UrlValidator urlValidator = new UrlValidator(schemes);
        if (!hostname.isEmpty()) {
            return urlValidator.isValid(hostname);
        } else {
            return false;
        }
    }

    // DONE: Validate security config
    private void validateSecurityConfigIds(final String configIds, final List<String> errors) {
        if ((configIds != null) && (configIds.isEmpty() == false)) {
            String[] configsArray = configIds.split(_AKAMAI_API_SECURITY_CONFIG_DELIMITER_);
            for (String id : configsArray) {
                if (!isDigits(id) || (isDigits(id) && Integer.parseInt(id) <= 0)) {
                    errors.add(format("%s is not valid Security Configuration ID(s)", id));
                }
            }
        }
    }

    // DONE: Log Splunk API call Failure message
    private void handleSplunkRestServiceFailure(final EventWriter ew, String log_level,
                                                final RequestMessage requestMessage, ResponseMessage response, final String endPoint) throws InputException {
        StringBuilder message = new StringBuilder();
        int statusCode = 0;
        StringBuilder responseMessage = new StringBuilder();

        if (response != null) {
            statusCode = response.getStatus();
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(response.getContent(), "UTF-8"))) {
                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    responseMessage.append(line);
                }
            } catch (IOException ioe) {
                logException(ew, ioe);
            }
        }
        message.append("Following end point failed.").append(" Service end point : ").append(endPoint).append(", Method : ")
                .append(requestMessage.getMethod()).append(", Request Message : ").append(requestMessage.getContent())
                .append(", Response Code :").append(statusCode).append(", Response :").append(responseMessage.toString());
        error(ew, log_level, message.toString());
        throw new InputException(message.toString());
    }

    // DONE: Log Akamai SIEM service failure message
    private void logAkamaiSIEMServiceFailure(final EventWriter ew, String log_level, final HttpRequest requestMessage,
                                             final String response, final String endPoint) {
        StringBuilder message = new StringBuilder();
        message.append("Following end point failed.").append(" Service end point : ").append(endPoint).append(", Method : ")
                .append("GET").append(", Content : ").append(response);
        error(ew, log_level, message.toString());
    }

    // DONE: Get offset, error count etc. from the kv store
    private stanza_state getValuesFromKVStore(final EventWriter ew, String log_level, final Service kvStoreService,
                                              final String inputName) throws InputException, IOException {
        info(ew, log_level, format("infoMsg=KV Service get...", ew));

        // Splunk class: HTTP request
        RequestMessage kvRequestMessage = new RequestMessage("GET");
        kvRequestMessage.getHeader().put("Content-Type", "application/json");

        // get offset value from the kvstore using the API
        ResponseMessage kvResponseMessage = kvStoreService
                .send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state", kvRequestMessage);

        debug(ew, log_level, format("infoMsg= KVStore response = %s", kvResponseMessage.getStatus()));

        // If error getting the kvsstore value, print in the error log
        if ((kvResponseMessage.getStatus() == HttpStatus.SC_OK
                || kvResponseMessage.getStatus() == HttpStatus.SC_CREATED) == false) {
            handleSplunkRestServiceFailure(ew, log_level, kvRequestMessage, kvResponseMessage,
                    "/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state");
        }

        info(ew, log_level, "infoMsg=Parse KVstore data...");
        stanza_state kvStoreStanza = null;

        // Received inputStream, read using BufferedReader
        try (BufferedReader bufferedReader =
                     new BufferedReader(new InputStreamReader(kvResponseMessage.getContent(), "UTF-8"))) {
            String line = null;
            boolean found = false;

            // Get kv store data
            while ((line = bufferedReader.readLine()) != null && !found) {
                try {
                    // deserialize JSON response using Jackson
                    stanza_state[] stanzas = mapper.readValue(line, stanza_state[].class);
                    for (stanza_state ss : stanzas) {
                        if (inputName.equalsIgnoreCase(ss.stanza)) {
                            kvStoreStanza = ss;
                            found = true;
                            break;
                        }
                    }
                } catch (Exception ex) {
                    logException(ew, ex);
                }
            }
        }
        info(ew, log_level, "infoMsg=Parse KVstore data...Complete");
        return kvStoreStanza;
    }

    // Update values in KV store with new offset and error count
    private stanza_state updateValuesInKVStore(final EventWriter ew, String log_level, final Service kvStoreService,
                                               final String inputName, final String newOffset, final Integer error_count) throws InputException, IOException {

        // Get stanza values from the kv store ( offset, error count etc.)
        stanza_state kvStoreStanza = getValuesFromKVStore(ew, log_level, kvStoreService, inputName);

        if (kvStoreStanza != null) {

            // Error count is 5 or more, clear the offset and the error count to update with the new offset value
            if (kvStoreStanza.error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_) {
                error(ew, log_level, format("infoMsg=%d  consecutive errors.  Clearing offset and error count",
                        _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_));
                kvStoreStanza.offset = "";
                kvStoreStanza.error_count = 0;
            } else {
                // Error count is from 0 to 4
                kvStoreStanza.offset = newOffset;

                // For successful response, reset the count to 0
                // For unsuccessful response, increase the error count
                if (error_count == 0) {
                    kvStoreStanza.error_count = 0;
                } else {
                    kvStoreStanza.error_count = kvStoreStanza.error_count + error_count;
                }
            }
            kvStoreStanza.stanza_change = "0";
            kvStoreStanza.stanza = inputName;

            // Write the new kv store stanza (offset value, error count etc.) to the kv store using the API
            RequestMessage requestMessage = new RequestMessage("POST");
            requestMessage.getHeader().put("Content-Type", "application/json");
            requestMessage.setContent(mapper.writeValueAsString(kvStoreStanza));

            ResponseMessage kvStoreServiceResponse = kvStoreService.send(String
                            .format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key),
                    requestMessage);
            debug(ew, log_level, format("infoMsg= response = %s", kvStoreServiceResponse.getStatus()));

            if ((kvStoreServiceResponse.getStatus() == HttpStatus.SC_OK
                    || kvStoreServiceResponse.getStatus() == HttpStatus.SC_CREATED) == false) {
                handleSplunkRestServiceFailure(ew, log_level, requestMessage, kvStoreServiceResponse, String
                        .format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key));
            }
        } else {

            // If kv store stanza is blank, just write to the kv store without error check
            kvStoreStanza = new stanza_state();
            kvStoreStanza._key = "";
            kvStoreStanza.offset = newOffset;
            kvStoreStanza.error_count = error_count;
            kvStoreStanza.stanza_change = "0";
            kvStoreStanza.stanza = inputName;

            debug(ew, log_level, String.format("kvStoreStanza=%s", mapper.writeValueAsString(kvStoreStanza)));

            RequestMessage requestMessage = new RequestMessage("POST");
            requestMessage.getHeader().put("Content-Type", "application/json");
            requestMessage.setContent(mapper.writeValueAsString(kvStoreStanza));

            ResponseMessage kvStoreServiceResponse = kvStoreService
                    .send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/", requestMessage);
            debug(ew, log_level, format("infoMsg= response = %s", kvStoreServiceResponse.getStatus()));

            if ((kvStoreServiceResponse.getStatus() == HttpStatus.SC_OK
                    || kvStoreServiceResponse.getStatus() == HttpStatus.SC_CREATED) == false) {
                handleSplunkRestServiceFailure(ew, log_level, requestMessage, kvStoreServiceResponse,
                        String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/"));
            }
        }
        return kvStoreStanza;
    }

    // DONE: Validate epoch time
    public void validateEpochTime(final String epochTime, final List<String> errors) {
        if (!isEmpty(epochTime)) {
            if (isDigits(epochTime)) {
                Integer value = Integer.valueOf(epochTime);
                if (value <= 0) {
                    errors.add(format("%s is not valid Epoch Time", epochTime));
                }
            } else {
                errors.add(format("%s is not valid Epoch Time", epochTime));
            }
        }
    }

    // DONE: Establishes a connection to a Splunk service and Get service for Akamai's app
    // DONE: Creates a new Service instance and authenticates the session using credentials passed in from the args map
    private Service getServiceForApp(final String session_key, final String app) {
        ServiceArgs akamaiServiceArgs = new ServiceArgs();
        akamaiServiceArgs.setHost("localhost");
        akamaiServiceArgs.setPort(8089);
        akamaiServiceArgs.setScheme("https");
        akamaiServiceArgs.setToken("Splunk " + session_key);
        akamaiServiceArgs.setApp(app);
        Service akamaiSplunkService = Service.connect(akamaiServiceArgs);
        return akamaiSplunkService;
    }

    // DONE: Get the value of the key from the HashMap
    private String getInputValueAsString(final Map<String, Parameter> inputMap, final String key) {
        Parameter parameter = inputMap.get(key);
        if (parameter != null) {
            return ((SingleValueParameter) parameter).getValue();
        }
        return null;
    }

    public class MyRunnable implements Runnable {

        private double runTime;
        private String sessionKey;
        private String log_level;
        private String inputName;
        private String _MASK_;
        private EventWriter ew;

        public MyRunnable(String sessionKey, String log_level, String inputName, String _MASK_, double runTime,
                          EventWriter ew) {
            this.sessionKey = sessionKey;
            this.log_level = log_level;
            this.inputName = inputName;
            this._MASK_ = _MASK_;
            this.ew = ew;
            this.runTime = runTime;
        }

        public void run() {

            String methodName = "MyRunnable.run";
            try {
                HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

                info(ew, log_level, format("infoMsg=%s, Begin client secret crypto", methodName));
                info(ew, log_level, format("infoMsg=%s, TA-Akamai_SIEM Service connect", methodName));
                Service akamaiSplunkService = getServiceForApp(sessionKey, "TA-Akamai_SIEM");

                RequestMessage akamaiRequestMessage = new RequestMessage("GET");
                akamaiRequestMessage.getHeader().put("Content-Type", "application/json");

                String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
                String modInputUrl = format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json",
                        URLEncoder.encode(inputStanza, "UTF-8"));
                String enableUrl = format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s/enable",
                        URLEncoder.encode(inputStanza, "UTF-8"));

                info(ew, log_level, format("infoMsg=%s, modInputUrl=", methodName, modInputUrl));
                ResponseMessage akamairm = akamaiSplunkService.send(modInputUrl, akamaiRequestMessage);
                info(ew, log_level, format("infoMsg=%s, status=%s", methodName, akamairm.getStatus()));

                try (BufferedReader akamaiReader = new BufferedReader(new InputStreamReader(akamairm.getContent(), "UTF-8"))) {
                    String line = null;
                    while ((line = akamaiReader.readLine()) != null) {
                        info(ew, log_level, format("infoMsg=%s, line=%s", methodName, line));
                        InputStanza is = mapper.readValue(line, InputStanza.class);
                        if (is != null) {
                            List<com.akamai.siem.Entry> entries = is.getEntry();
                            if (entries != null) {
                                for (com.akamai.siem.Entry entry : entries) {
                                    Content content = entry.getContent();
                                    String client_secret = content.getClientSecret();
                                    String access_token = content.getAccessToken();
                                    String client_token = content.getClientToken();
                                    if (!(_MASK_.equals(client_secret) && _MASK_.equals(access_token) && _MASK_.equals(client_token))) {
                                        warn(ew, log_level, " [client secret | access token | clientToken]  is not masked.");
                                        PasswordCollection pColl = akamaiSplunkService.getPasswords();
                                        if (pColl == null) {
                                            warn(ew, log_level, "pColl is null");
                                        }
                                        // info(ew, log_level, "923");
                                        String client_secret_username = "client_secret";
                                        String access_token_username = "access_token";
                                        String client_token_username = "client_token";

                                        Map<String, String> userNamePasswordMap = new HashMap<String, String>();
                                        if (!_MASK_.equals(client_secret)) {
                                            userNamePasswordMap.put(client_secret_username, client_secret);
                                        }
                                        if (!_MASK_.equals(access_token)) {
                                            userNamePasswordMap.put(access_token_username, access_token);
                                        }
                                        if (!_MASK_.equals(client_token)) {
                                            userNamePasswordMap.put(client_token_username, client_token);
                                        }

                                        for (String key : userNamePasswordMap.keySet()) {

                                            String keyWithReamlm = format("%s:%s:", inputStanza, key);
                                            // info(ew, log_level, keyWithReamlm);
                                            if (pColl != null) {

                                                // info(ew, log_level, keyWithReamlm);
                                                if (pColl.containsKey(keyWithReamlm)) {
                                                    // info(ew, log_level, key);
                                                    pColl.remove(keyWithReamlm);
                                                }
                                                pColl.create(key, userNamePasswordMap.get(key), inputStanza);
                                            }

                                        }

                                        content.setClientSecret(_MASK_);
                                        content.setAccessToken(_MASK_);
                                        content.setClientToken(_MASK_);


                                        RequestMessage postMessage = new RequestMessage("POST");
                                        postMessage.getHeader().put("Content-Type", "application/x-www-form-urlencoded");

                                        StringBuilder builder = new StringBuilder().append("access_token=")
                                                .append(URLEncoder.encode(content.getAccessToken(), "UTF-8")).append("&client_secret=")
                                                .append(URLEncoder.encode(content.getClientSecret(), "UTF-8")).append("&client_token=")
                                                .append(URLEncoder.encode(content.getClientToken(), "UTF-8")).append("&hostname=")
                                                .append(URLEncoder.encode(content.getHostname(), "UTF-8"))
                                                .append("&security_configuration_id_s_=")
                                                .append(URLEncoder.encode(content.getSecurityConfigurationIdS(), "UTF-8"));

                                        if (content.getFinalEpochTime() != null) {
                                            builder.append("&final_epoch_time=")
                                                    .append(URLEncoder.encode(content.getFinalEpochTime().toString(), "UTF-8"));
                                        }
                                        if (content.getInitialEpochTime() != null) {
                                            builder.append("&initial_epoch_time=")
                                                    .append(URLEncoder.encode(content.getInitialEpochTime().toString(), "UTF-8"));
                                        }
                                        if (!isEmpty(content.getHost())) {
                                            builder.append("&host=").append(URLEncoder.encode(content.getHost(), "UTF-8"));
                                        }
                                        if (!isEmpty(content.getIndex())) {
                                            builder.append("&index=").append(URLEncoder.encode(content.getIndex(), "UTF-8"));
                                        }

                                        if (!isEmpty(content.getInterval())) {
                                            builder.append("&interval=").append(URLEncoder.encode(content.getInterval(), "UTF-8"));
                                        }

                                        if (content.getLimit() != null) {
                                            builder.append("&limit=").append(URLEncoder.encode(content.getLimit().toString(), "UTF-8"));
                                        }

                                        if (!isEmpty(content.getLogLevel())) {
                                            builder.append("&log_level=").append(URLEncoder.encode(content.getLogLevel(), "UTF-8"));
                                        }

                                        if (!isEmpty(content.getSourcetype())) {
                                            builder.append("&sourcetype=").append(URLEncoder.encode(content.getSourcetype(), "UTF-8"));
                                        }
                                        String formurlencoded = builder.toString();

                                        // debug(ew, log_level, format("infoMsg=%s,formurlencoded=%s", methodName, formurlencoded));
                                        // info(ew, log_level, format("infoMsg=%s, line=%s", methodName, "fdlksjfdlkf"));
                                        postMessage.setContent(formurlencoded);
                                        ResponseMessage rm = akamaiSplunkService
                                                .send(format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json",
                                                        URLEncoder.encode(inputStanza, "UTF-8")), postMessage);
                                        debug(ew, log_level, "getStatus=" + String.valueOf(rm.getStatus()));

                                    }
                                    if (!isEmpty(content.getInterval())) {
                                        double intervalInSeconds = Double.parseDouble(content.getInterval());
                                        double realTimeInSeconds = runTime / SECONDS.toNanos(1);
                                        if (realTimeInSeconds >= intervalInSeconds) {
                                            info(ew, log_level,
                                                    String.format("Run time [%.2f s] exceeds interval [%.2f s].  Calling enable endpoint...",
                                                            realTimeInSeconds, intervalInSeconds));
                                            RequestMessage enableRequest = new RequestMessage("POST");
                                            akamaiSplunkService.send(enableUrl, enableRequest);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                Main.logException(ew, ex);
            }
        }
    }
}
