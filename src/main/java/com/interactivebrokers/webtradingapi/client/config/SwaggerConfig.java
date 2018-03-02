package com.interactivebrokers.webtradingapi.client.config;

import org.springframework.context.annotation.*;

import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {                                    
    @Bean
    public Docket api() { 
        return new Docket(DocumentationType.SWAGGER_2)  
          .select()                                  
          .apis(RequestHandlerSelectors.basePackage("com.interactivebrokers.webtradingapi.client.controllers"))              
          .paths(PathSelectors.regex("/webtradingapi/.*"))                          
          .build();                                           
    }
}