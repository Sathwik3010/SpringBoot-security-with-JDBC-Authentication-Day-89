package com.codegnan.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRestController {

	@GetMapping("/admin")
	public String admin() {
		return "<h3>Welcome Admin:)</h3>";
	}
	
	@GetMapping("/user")
	public String user() {
		return "<h3>Welcome User:)</h3>";
	}
	
	@GetMapping("/")
	public String welcome() {
		return "<h3>Welcome:)</h3>";
	}
}
