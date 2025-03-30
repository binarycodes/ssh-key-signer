package io.binarycodes.homelab.lib;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class DeviceFlowStartResponse {
    private String deviceCode;
    private String userCode;
    private String verificationUri;
    private String verificationUriComplete;
    private int expiresIn;
    private int interval;
}
