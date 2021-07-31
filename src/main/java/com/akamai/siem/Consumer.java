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
public class Consumer implements Callable<Double> {
    private final BlockingQueue<String> queue;
    private final BlockingQueue<Event> eventQueue;
    private volatile Boolean done;
    private String inputName;
    private EventWriter ew;
    private Integer threadId;
    private ObjectMapper mapper;
    private double runningEdgeGridTime;
    final long startEdgeGrid;

    public Consumer(BlockingQueue<String> queue, BlockingQueue<Event> eventQueue, String inputName, EventWriter ew,
                    Integer threadId) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        this.startEdgeGrid = System.nanoTime();
        this.queue = queue;
        this.done = false;
        this.inputName = inputName;
        this.ew = ew;
        this.threadId = threadId;
        this.eventQueue = eventQueue;
        this.mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public Double call() {

        String firstEvent = null;
        while (done == false) {
            try {
                firstEvent = queue.poll(5, TimeUnit.MILLISECONDS);

                if (firstEvent != null) {
                    double startEvent = System.nanoTime();

                    if ("poisonPill".equals(firstEvent) == true) {
                        done = true;
                    } else {

                        // Get the raw value
                        Raw raw = mapper.readValue(firstEvent, Raw.class);

                        // Converts the row value to the format to be showen in Splunk
                        raw.processRaw();

                        //
                        if (raw.getOffset() != null) {
                            ew.synchronizedLog(EventWriter.INFO, format("found new offset: %s", raw.getOffset()));
                            Main.staticOffset = raw.getOffset();
                        } else {

                            // Put processed events in the event Queue
                            String payLoad = mapper.writeValueAsString(raw);
                            Event event = new Event();
                            event.setStanza(inputName);
                            event.setData(payLoad);
                            this.eventQueue.put(event);
                        }
                    }
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
