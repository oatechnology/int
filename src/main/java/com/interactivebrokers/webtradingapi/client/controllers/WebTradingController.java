package com.interactivebrokers.webtradingapi.client.controllers;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.condition.ConsumesRequestCondition;

import com.interactivebrokers.webtradingapi.client.model.Message;
import com.interactivebrokers.webtradingapi.client.model.User;
import com.interactivebrokers.webtradingapi.client.start.ConsumerStart;

import io.swagger.models.Response;

@RestController
@RequestMapping("/webtradingapi")
public class WebTradingController {

	private static final String template = "Hello, %s!";
	private final AtomicLong counter = new AtomicLong();

	@RequestMapping(value = "/usertest", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity getUserTest(@RequestBody User user) {
 
		if(user.getPassword().isEmpty() ||  user.getPassword() == null
			|| 	user.getUsername().isEmpty() ||  user.getUsername() == null )
			   return ResponseEntity.status(HttpStatus.FORBIDDEN).body("error".getBytes());
		else
		   return ResponseEntity.status(HttpStatus.OK).body(user);
	
	}
	
	 @RequestMapping("hello")
    public String sayHello(){
        return ("Hello , SpringBoot API");
    }
	
	/*
	 * get live sessioon token
	 * 
	 */
	@RequestMapping(value = "/livesessiontoken", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity getLiveSessionToken(@RequestBody User user) {
		ConsumerStart s = new ConsumerStart();
		Message msg = null;
		try {
			msg = s.getLiveSessionToken(user.getUsername(), user.getPassword());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body( e.getMessage().getBytes());

		}
		if(msg != null) {
		   return ResponseEntity.status(HttpStatus.OK).body(msg);
		}
		
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body( "There is an Error".getBytes());

	}

}
