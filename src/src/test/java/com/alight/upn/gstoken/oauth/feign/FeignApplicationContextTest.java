package com.alight.upn.gstoken.oauth.feign;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
class FeignApplicationContextTest {

    @Test
    void testSetAndGetApplicationContext() {
        // Arrange
        ApplicationContext mockContext = Mockito.mock(ApplicationContext.class);
        FeignApplicationContext feignContext = new FeignApplicationContext();

        // Act
        feignContext.setApplicationContext(mockContext);
        ApplicationContext returnedContext = FeignApplicationContext.getAppContext();

        // Assert
        assertNotNull(returnedContext, "ApplicationContext should not be null");
        assertEquals(mockContext, returnedContext, "Returned context should match the mock");
    }
}

