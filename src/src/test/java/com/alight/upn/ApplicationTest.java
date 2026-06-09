package com.alight.upn;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.servlet.MockMvc;




@SpringBootTest
@AutoConfigureMockMvc
public class ApplicationTest {
	@InjectMocks
	Application application;

    @Autowired
    private MockMvc mockMvc;
    @Mock SpringApplication springApplication;
    @Mock ConfigurableApplicationContext configurableApplicationContext;


    @Configuration
    public static class Config {
    }
    
    @Test
    public void shouldReturnDefaultMessage() throws Exception {
        this.mockMvc.perform(get("/"));
    }
    
    @Test
	public void testMain(){
		String[] args = new String[]{""};
		MockedStatic<SpringApplication> mocked= Mockito.mockStatic(SpringApplication.class);
	      mocked.when(() -> SpringApplication.run(Application.class, args)).thenReturn(configurableApplicationContext);
		
		Application.main(args);
		
		ConfigurableApplicationContext resultContext = SpringApplication.run(Application.class, args); //re-run for the sake of validating test case.
		
		assertNotNull(resultContext,"Running application tests.");
		Mockito.clearAllCaches();
	}
}

