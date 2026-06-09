package com.alight.upn.gstoken.oauth.helper;

import com.alight.portal.core.udp.v2.dto.person.PersonsV2;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PersonV2HelperTest {

    @Mock
    private PersonsV2FeignClient personV2Response;

    @InjectMocks
    private PersonV2Helper personV2Helper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetGlobalPersonIdentifier_success() {
        PersonsV2 mockPerson = new PersonsV2();
        mockPerson.setGlobalPersonIdentifier("GPI123");

        when(personV2Response.getPersonsV2Response())
                .thenReturn(ResponseEntity.ok(mockPerson));

        String result = personV2Helper.getGlobalPersonIdentifier();
        assertEquals("GPI123", result);
    }

    @Test
    void testGetGlobalPersonIdentifier_nullResponse() {
        when(personV2Response.getPersonsV2Response()).thenReturn(null);

        String result = personV2Helper.getGlobalPersonIdentifier();
        assertNull(result);
    }

    @Test
    void testGetGlobalPersonIdentifier_nullBody() {
        when(personV2Response.getPersonsV2Response())
                .thenReturn(ResponseEntity.ok(null));

        String result = personV2Helper.getGlobalPersonIdentifier();
        assertNull(result);
    }

    @Test
    void testGetGlobalPersonIdentifier_exceptionThrown() {
        when(personV2Response.getPersonsV2Response())
                .thenThrow(new RuntimeException("Service unavailable"));

        String result = personV2Helper.getGlobalPersonIdentifier();
        assertNull(result);
    }
}
