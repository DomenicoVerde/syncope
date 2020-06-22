package org.apache.core.spring;

import static org.mockito.Mockito.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.syncope.common.lib.policy.DefaultAccountRuleConf;
import org.apache.syncope.core.spring.policy.AccountPolicyException;
import org.apache.syncope.core.spring.policy.DefaultAccountRule;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

@RunWith(MockitoJUnitRunner.class)
public class DefaultAccountRuleTest extends DefaultAccountRule {

	@Mock
	private DefaultAccountRuleConf conf;
	
	@Before
	public void init() {
		// Mocking a conf class to implement the following policy:
		// username can have only lowercase characters
		// This will be the default conf for other tests
		conf = mock(DefaultAccountRuleConf.class, new Answer<Object>() {
			@Override public Object answer(InvocationOnMock invocation) {
				if (invocation.getMethod().getName().equals("Length")) {
					//no limits set in length
					return 0;
				} else if (invocation.getMethod().getName().contains("isAllLowerCase")) {
					return true;
				} else if (invocation.getMethod().getName().contains("isAllUpperCase")) {
					return false;
				} else if (invocation.getMethod().getName().contains("NotPermitted")) {
					return new ArrayList<String>();
				} else if (invocation.getMethod().getName().contains("get")) {
					return null;
				}
				return null;
			}
		});

		super.setConf(conf);
	}
	
	// Category Partition Test Cases (CP)
	@Test
	public void test1CP() {
		boolean passed = false;
		try {
			super.enforce(null, null);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test2CP() {
		boolean passed = false;
		Set<String> wordsNotPermitted = new HashSet<String>();
		wordsNotPermitted.add("word");
		wordsNotPermitted.add("123");
		try {
			super.enforce("", wordsNotPermitted);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test3CP() {
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		wordsNotPermitted.add("word");
		wordsNotPermitted.add("123");
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void test4CP() {
		boolean passed = false;
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		wordsNotPermitted.add("nico");
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	//Other tests to reach adequacy criteria
	@Test
	public void usernameLengthTest() {
		// Let allow only usernames between 4 and 6 chars
		when(conf.getMinLength()).thenReturn(4);
		when(conf.getMaxLength()).thenReturn(6);
		
		Set<String> wordsNotPermitted = new HashSet<String>();
		boolean tooShort = false;
		boolean tooLong = false;
		String shortUsername = "dom";
		String longUsername = "domenic";
		String rightUsername1 = "dome";
		String rightUsername2 = "domeni";
		
		try {
			super.enforce(shortUsername, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			if (e.getMessage().contains("too short")) {
				tooShort = true;
			}
		}
		
		try {
			super.enforce(longUsername, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			if (e.getMessage().contains("too long")) {
				tooLong = true;
			}
		}
		
		try {
			super.enforce(rightUsername1, wordsNotPermitted);
			super.enforce(rightUsername2, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			Assert.fail();
		}
		
		Assert.assertTrue(tooLong && tooShort); 
	}
		
	@Test
	public void allUppercaseTest() {
		// Tests the control about allowing only lowercase letters		
		Set<String> wordsNotPermitted = new HashSet<String>();
		String username = "Domenico";
		String username2 = username.toLowerCase();
		boolean passed = false;
		
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
		
		try {
			super.enforce(username2, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			Assert.fail();
		}
	}
	
	@Test
	public void allLowercaseTest() {
		// Tests the control about allowing only uppercase letters
		when(conf.isAllUpperCase()).thenReturn(true);
		when(conf.isAllLowerCase()).thenReturn(false);
		
		Set<String> wordsNotPermitted = new HashSet<String>();
		String username = "Domenico";
		String username2 = username.toUpperCase();
		boolean passed = false;
		
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
		
		try {
			super.enforce(username2, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			Assert.fail();
		}
	}
	
	@Test
	public void prefixTest() {
		// Tests the control about prefixes not permitted
		// invalid username:
		List<String> prefixes = new ArrayList<String>();
		prefixes.add("dome");
		Set<String> wordsNotPermitted = new HashSet<String>();
		String username = "domenico";
		boolean passed = false;
		
		when(conf.getPrefixesNotPermitted()).thenReturn(prefixes);
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
		
		// valid username 
		username ="nico";
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void suffixTest() {
		// Tests the control about suffixes not permitted
		// invalid username
		List<String> suffixes = new ArrayList<String>();
		suffixes.add("nico");
		Set<String> wordsNotPermitted = new HashSet<String>();
		String username = "domenico";
		boolean passed = false;
		
		when(conf.getSuffixesNotPermitted()).thenReturn(suffixes);
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
		
		// valid username 
		username ="dome";
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void patternTest() {
		// Tests the control about patterns not permitted
		Set<String> wordsNotPermitted = new HashSet<String>();
		String username = "domenico";
		boolean passed = false;

		when(conf.getPattern()).thenReturn("eni");
		try {
			super.enforce(username, wordsNotPermitted);
		} catch (AccountPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
}
