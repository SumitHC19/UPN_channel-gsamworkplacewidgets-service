package com.alight.upn.gstoken.oauth.feign;

import com.aonhewitt.beans.GenericRequestBean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
class ChannelWidgetConfigurationClientTest {

    @Test
    void testGetListOfAsset() {
        // Arrange
        ChannelWidgetConfigurationClient mockClient = Mockito.mock(ChannelWidgetConfigurationClient.class);
        GenericRequestBean requestBean = new GenericRequestBean();
        // Optionally set fields on requestBean here

        List<Map<Object, Object>> mockResponse = new ArrayList<>();
        Map<Object, Object> config = new HashMap<>();
        config.put("widgetId", "123");
        config.put("widgetName", "Test Widget");
        mockResponse.add(config);

        Mockito.when(mockClient.getListOfAsset(requestBean)).thenReturn(mockResponse);

        // Act
        List<Map<Object, Object>> result = mockClient.getListOfAsset(requestBean);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(1, result.size(), "Result size should be 1");
        assertEquals("123", result.get(0).get("widgetId"));
        assertEquals("Test Widget", result.get(0).get("widgetName"));
    }
}
