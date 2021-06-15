package com.akamai.siem;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class BasicTest {
  
  @Test
  public void testAutomaticSupportNewFields() throws IOException {
    ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    String input =
        "{\"type\":\"akamai_siem\",\"format\":\"json\",\"version\":\"1.0\",\"attackData\":{\"configId\":\"48894\",\"policyId\":\"akrs_88128\",\"clientIP\":\"2001:4878:8037:100::207\",\"rules\":\"NjAwMzcyNTA%3d\",\"ruleVersions\":\"\",\"ruleMessages\":\"VGVzdEN1c3RvbUZpZWxkcw%3d%3d\",\"ruleTags\":\"Q1VTVE9NL1RFU1Q%3d\",\"ruleData\":\"\",\"ruleSelectors\":\"\",\"ruleActions\":\"ZGVueQ%3d%3d\"},\"httpMessage\":{\"requestId\":\"15c0786\",\"start\":\"1601664896\",\"protocol\":\"HTTP/1.1\",\"method\":\"GET\",\"host\":\"actions.alert.konaqa.com\",\"port\":\"80\",\"path\":\"/index.spl\",\"requestHeaders\":\"\",\"status\":\"403\",\"bytes\":\"290\",\"responseHeaders\":\"Mime-Version%3a%201.0%0d%0aAkamai-X-WAF-Deny-Rules%3a%2060037250%0d%0aAkamai-X-WAF-Alerted-Rules%3a%20%0d%0aAkamai-X-WAF-Alerted-Rules-Versions%3a%20%0d%0aAkamai-X-WAF-Deny-Rule-Version%3a%2060037250_%0d%0aAkamai-X-WAF-Triggered-Actions%3a%20deny%0d%0aAkamai-X-WAF-Triggered-Rule-Versions%3a%2060037250_%0d%0aAkamai-X-WAF-Triggered-Rules%3a%2060037250%0d%0aAkamai-X-Cumulative-Regex-Time%3a%20%0d%0aAkamai-X-Request-ID%3a%2015c0786%0d%0a\"},\"geo\":{\"continent\":\"NA\",\"country\":\"US\",\"city\":\"CAMBRIDGE\",\"regionCode\":\"MA\",\"asn\":\"6461\"},\"userRiskData\":{\"uuid\":\"a5a7f0d1-d033-4c15-b976-06061669123a\",\"status\":\"4\",\"score\":\"0\",\"risk\":\"\",\"trust\":\"device_id:8cc180d494bb55f9d713e99b4dd2713a013f43bd|geo:US|os:Mac%20OS%20X%2010|browser:Chrome%2085|asnum:15169\",\"general\":\"\",\"allow\":\"0\"},\"clientData\":{\"appBundleId\":\"testId\",\"appVersion\":\"1\",\"clientType\":\"webclient\",\"sdkVersion\":\"1\"},\"botData\":{\"botScore\":\"50\",\"responseSegment\":\"0\"},\"key1\":\"value1\",\"key2\":{\"innerKey1\":\"innerValue1\",\"innerKey2\":{\"someKey\":\"someValue\"}},\"arrayKey\":[{\"arrayKey1\":\"arrayValue1\"},{\"arrayKey2\":{\"innerArrayKey1\":\"innerArrayValue1\"}}]}";

    Raw raw = mapper.readValue(input, Raw.class);
    raw.processRaw();

    String splunkEvent = mapper.writeValueAsString(raw);

    System.out.println(splunkEvent);

    // check if splunkEvent contains newField userRiskData
    assertTrue(splunkEvent.contains(
        "\"userRiskData\":{\"uuid\":\"a5a7f0d1-d033-4c15-b976-06061669123a\",\"status\":\"4\",\"score\":\"0\",\"risk\":\"\",\"trust\":\"device_id:8cc180d494bb55f9d713e99b4dd2713a013f43bd|geo:US|os:Mac OS X 10|browser:Chrome 85|asnum:15169\",\"general\":\"\",\"allow\":\"0\"}"));

    // check if splunkEvent contains newField clientData
    assertTrue(splunkEvent.contains(
        "\"clientData\":{\"appBundleId\":\"testId\",\"appVersion\":\"1\",\"clientType\":\"webclient\",\"sdkVersion\":\"1\"}"));

    // check if splunkEvent contains newField botData
    assertTrue(splunkEvent.contains("\"botData\":{\"botScore\":\"50\",\"responseSegment\":\"0\"}"));
  }
  
}
