package com.akamai.siem;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.splunk.modularinput.Event;
import com.splunk.modularinput.EventWriter;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;

// Define the thread task here
// Task: Take one line from the queue and process it
public class Consumer implements Callable<Double> {
    private final BlockingQueue<String> queue;

    // eventQueue has processed Splunk events
    private final BlockingQueue<Event> eventQueue;
    private volatile Boolean done;
    private String inputName;
    private EventWriter ew;
    private Integer threadId;
    private ObjectMapper mapper;
    private double runningEdgeGridTime;
    final long startEdgeGrid;

    // queue: Data to be processed
    // EventQueue: Processed events to be sent to Splunk
    public Consumer(BlockingQueue<String> queue, BlockingQueue<Event> eventQueue, String inputName, EventWriter ew,
                    Integer threadId) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        this.startEdgeGrid = System.nanoTime();
        this.queue = queue;
        this.done = false;
        this.inputName = inputName;
        this.ew = ew;
        this.threadId = threadId;
        this.eventQueue = eventQueue;

        // ObjectMapper class helps to serialize (Java object to JSON) or deserialize (JSON to Java object)
        this.mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    // Process one event (URL decode and base 64 decode) from the queue
    // Returns time to process one event
    public Double call() {

        String firstEvent = null;

        while (done == false) {
            try {

                // queue: Data to be processed
                // Get the data from the queue for processing
                firstEvent = queue.poll(5, TimeUnit.MILLISECONDS);

                if (firstEvent != null) {

                    // start of processing one line
                    double startEvent = System.nanoTime();

                    // If all the events are processed
                    if ("poisonPill".equals(firstEvent) == true) {
                        done = true;
                    } else {

                        // Convert JSON to Java object of the class Raw
                        Raw raw = mapper.readValue(firstEvent, Raw.class);

                        // Converts the row value to the format to be showen in Splunk
                        // For e.g URL decode and base 64 conversion
                        raw.processRaw();

                        // Set the offset in the Main class
                        if (raw.getOffset() != null) {
                            ew.synchronizedLog(EventWriter.INFO, format("found new offset: %s", raw.getOffset()));
                            Main.staticOffset = raw.getOffset();
                        } else {

                            // Put processed events in the eventQueue
                            // Convert Java object to JSON
                            String payLoad = mapper.writeValueAsString(raw);

                            // Splunk event class
                            Event event = new Event();
                            event.setStanza(inputName);
                            event.setData(payLoad);

                            // Put the processed Splunk events in another BlockingQueue
                            this.eventQueue.put(event);
                        }
                    }

                    // time to process one line
                    this.runningEdgeGridTime += System.nanoTime() - startEvent;
                }
            } catch (InterruptedException ie) {
                done = true;
            } catch (Exception ex) {
                Main.logException(ew, ex);
                Main.logException(ew, new Exception(firstEvent));
            }
        }

        return (runningEdgeGridTime);
    }
}
