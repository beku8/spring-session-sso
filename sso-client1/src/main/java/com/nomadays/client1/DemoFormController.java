package com.nomadays.client1;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 
 * Just regular controller to ensure that CSRF token is working properly.
 * @author beku
 *
 */
@Controller
@RequestMapping("/form")
public class DemoFormController {

	@RequestMapping
	public String get(){
		return "form";
	}
	
	@RequestMapping(method=RequestMethod.POST)
	public String post(Model model){
		model.addAttribute("success", true);
		return "form";
	}
}
