package com.akamai.siem;

import static org.apache.commons.lang3.StringUtils.isBlank;

public class UserRiskData {
  private String uuid;
  private String status;
  private String score;
  private String risk;
  private String trust;
  private String general;
  private String allow;
  
  public void processRaw() {
    this.trust = decode(this.trust);
    this.risk = decode(this.risk);
    this.general = decode(this.general);
  }
  
  private String decode(String s) {
    String urlDecodeValue = s;
    try {
      if (!isBlank(s)) {
        urlDecodeValue = java.net.URLDecoder.decode(s, "UTF-8");
      }
    } catch (Exception ex) {
    }
    return urlDecodeValue;
  }
  
  public String getUuid() {
    return uuid;
  }
  public void setUuid(String uuid) {
    this.uuid = uuid;
  }
  public String getStatus() {
    return status;
  }
  public void setStatus(String status) {
    this.status = status;
  }
  public String getScore() {
    return score;
  }
  public void setScore(String score) {
    this.score = score;
  }
  public String getRisk() {
    return risk;
  }
  public void setRisk(String risk) {
    this.risk = risk;
  }
  public String getTrust() {
    return trust;
  }
  public void setTrust(String trust) {
    this.trust = trust;
  }
  public String getGeneral() {
    return general;
  }
  public void setGeneral(String general) {
    this.general = general;
  }
  public String getAllow() {
    return allow;
  }
  public void setAllow(String allow) {
    this.allow = allow;
  }

  @Override
  public String toString() {
    return "UserRiskData [uuid=" + uuid + ", status=" + status + ", score=" + score + ", risk=" + risk + ", trust="
        + trust + ", general=" + general + ", allow=" + allow + "]";
  }
  
}
