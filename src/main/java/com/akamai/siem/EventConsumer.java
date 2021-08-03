package com.akamai.siem;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import com.splunk.modularinput.Event;
import com.splunk.modularinput.EventWriter;

// Define the thread task here
// Gets one event at a time from eventQueue
// Sends it to Splunk by calling Splunk's synchronizedWriteEvent method
public class EventConsumer implements Runnable {

  private final BlockingQueue<Event> eventQueue;
  private volatile Boolean done;
  private EventWriter ew;

  public EventConsumer(BlockingQueue<Event> eventQueue, EventWriter ew)
      throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    this.done = false;
    this.ew = ew;

    this.eventQueue = eventQueue;
  }

  @Override
  public void run() {

    while (done == false) {
      try {

        // Get the processed data
        Event firstEvent = eventQueue.poll(5, TimeUnit.MILLISECONDS);

        if (firstEvent != null) {
          if ("poisonPill".equals(firstEvent.getSourceType())) {
            // ew.synchronizedLog(EventWriter.INFO,format("poisonPill on thread %d", this.threadId));
            done = true;
          } else {
            // Splunk: writes an Event object to Splunk.
            ew.synchronizedWriteEvent(firstEvent);
          }
        }
      } catch (InterruptedException ie) {
        done = true;
      } catch (Exception ex) {
        Main.logException(ew, ex);
      }
    }
  }
}
