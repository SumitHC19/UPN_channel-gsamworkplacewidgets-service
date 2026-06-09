package com.alight.upn.gstoken.oauth.constant;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class GSAMConstantsTest {

    @Test
    void testConstantsValues() {
        assertEquals("GSAM:", GSAMConstants.REDIS_KEY_GSAM);
        assertEquals("", GSAMConstants.BLANK);
        assertEquals(":", GSAMConstants.COLON);
        assertEquals("ACCESSTOKEN", GSAMConstants.GSAM_ACCESS_TOKEN);
        assertEquals("alightColleagueSessionToken", GSAMConstants.COLLEAGUE_SESSION_TOKEN);
        assertEquals("configset", GSAMConstants.CONFIG_SET);
        assertEquals("IRA_RACF_AUTH_PROFILE", GSAMConstants.IRA_RACF_AUTH_PROFILE_TXT);
        assertEquals("text_uce", GSAMConstants.TEXT_UCE);
        assertEquals("credentials.racf.id", GSAMConstants.CRED_RACF_ID);
        assertEquals("alightRequestHeader", GSAMConstants.ALIGHT_REQUEST_HEADER);
        assertEquals("alightPersonSessionToken", GSAMConstants.PERSON_SESSION_TOKEN);
        assertEquals("Access-Control-Expose-Headers", GSAMConstants.ACCESS_CONTROL_EXPOSE_HEADERS);
    }

}
