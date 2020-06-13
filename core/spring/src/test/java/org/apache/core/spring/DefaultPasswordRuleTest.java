package org.apache.core.spring;

import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.apache.syncope.core.spring.policy.PasswordPolicyException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(MockitoJUnitRunner.class)
public class DefaultPasswordRuleTest extends DefaultPasswordRule {
	
	@Mock
	private DefaultPasswordRuleConf conf;
	
	@Before
	public void init() {
		// Mocking a conf class to implement the following policy:
		// password must be between 8 and 16 characters
		conf = mock(DefaultPasswordRuleConf.class, new Answer<Object>() {
			@Override public Object answer(InvocationOnMock invocation) {
				if (invocation.getMethod().getName().equals("getMinLength")) {
					return 8;
			    } else if (invocation.getMethod().getName().equals("getMaxLength")) {
			    	return 16;
				} else if (invocation.getMethod().getName().contains("is")) {
					return false;
				} else if (invocation.getMethod().getName().contains("get")) {
					return new ArrayList<String>();
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
			super.enforce(null, null, null);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test2CP() {
		boolean passed = false;
		String clear = "123456789";
		try {
			super.enforce(clear, "", null);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test3CP() {
		boolean passed = false;
		String clear = "1234567";
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		wordsNotPermitted.add("abc");
		wordsNotPermitted.add("def");
		try {
			super.enforce(clear, username, wordsNotPermitted);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test4CP() {
		boolean passed = false;
		String clear = "12345678";
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		wordsNotPermitted.add("abc");
		wordsNotPermitted.add("def");
		wordsNotPermitted.add("12345678");
		try {
			super.enforce(clear, username, wordsNotPermitted);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void test5CP() {
		String clear = "123456789012345";
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		try {
			super.enforce(clear, username, wordsNotPermitted);
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void test6CP() {
		String clear = "1234567890123456";
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		try {
			super.enforce(clear, username, wordsNotPermitted);
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void test7CP() {
		boolean passed = false;
		String clear = "12345678901234567";
		String username = "domenico";
		Set<String> wordsNotPermitted = new HashSet<String>();
		try {
			super.enforce(clear, username, wordsNotPermitted);
		} catch (Exception e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	//Other tests to reach adequacy criteria
	@Test
	public void passwordLengthTest() {
		// Covering condition: No limits set for password
		when(conf.getMinLength()).thenReturn(0);
		when(conf.getMaxLength()).thenReturn(0);
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (Exception e) {
			Assert.fail();
		}
	}
	
	@Test
	public void usernameTest() {
		// Let the password be equal to the username
		when(conf.isUsernameAllowed()).thenReturn(true);
		
		//Covering condition username = password
		try {
			super.enforce("domenico", "domenico", new HashSet<String>());
		} catch (Exception e) {
			Assert.fail();
		}
		
		when(conf.isUsernameAllowed()).thenReturn(false);
		boolean passed = false;
		try {
			super.enforce("domenico", "domenico", new HashSet<String>());
		} catch (Exception e) {
			passed = true;
		}
		
		//Covering condition username = null
		try {
			super.enforce("password", null, new HashSet<String>());
		} catch (Exception e) {
			Assert.fail();
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void requiredDigitTest() {
		when(conf.isDigitRequired()).thenReturn(true);
		try {
			super.enforce("password1", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void requiredLowercaseTest() {
		when(conf.isLowercaseRequired()).thenReturn(true);
		try {
			super.enforce("Password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("PASSWORD", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void requiredUppercaseTest() {
		when(conf.isUppercaseRequired()).thenReturn(true);
		try {
			super.enforce("Password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void prefixTest() {
		// Tests the control about prefixes not permitted
		List<String> prefixes = new ArrayList<String>();
		prefixes.add("pass");
		boolean passed = false;	
		when(conf.getPrefixesNotPermitted()).thenReturn(prefixes);
		
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void suffixTest() {
		// Tests the control about suffixes not permitted
		List<String> suffixes = new ArrayList<String>();
		suffixes.add("word");
		boolean passed = false;
		when(conf.getSuffixesNotPermitted()).thenReturn(suffixes);
		
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
			passed = true;
		}
		
		Assert.assertTrue(passed);
	}
	
	@Test
	public void mustStartOrNotWithDigitTest() {
		//Password must start with a digit
		when(conf.isMustStartWithDigit()).thenReturn(true);
		try {
			super.enforce("0password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not start with a digit
		when(conf.isMustStartWithDigit()).thenReturn(false);
		when(conf.isMustntStartWithDigit()).thenReturn(true);
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("0password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void mustEndOrNotWithDigitTest() {
		//Password must end with a digit
		when(conf.isMustEndWithDigit()).thenReturn(true);
		try {
			super.enforce("password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not end with a digit
		when(conf.isMustEndWithDigit()).thenReturn(false);
		when(conf.isMustntEndWithDigit()).thenReturn(true);
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void alphanumericOccurrenceTest() {
		//Password must contain at least one alphanumeric char
		when(conf.isAlphanumericRequired()).thenReturn(true);
		try {
			super.enforce("password0.,;:{};", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("-.,;:{};", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not contain at least one non-alphanumeric char
		when(conf.isAlphanumericRequired()).thenReturn(false);
		when(conf.isNonAlphanumericRequired()).thenReturn(true);
		try {
			super.enforce("Password0.", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("Password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void mustStartOrNotWithAlphaTest() {
		//Password must start with an alphanumeric char
		when(conf.isMustStartWithAlpha()).thenReturn(true);
		try {
			super.enforce("Password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce(".password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not start with an alphanumeric
		when(conf.isMustStartWithAlpha()).thenReturn(false);
		when(conf.isMustntStartWithAlpha()).thenReturn(true);
		try {
			super.enforce(".password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("0password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void mustEndOrNotWithAlphaTest() {
		//Password must end with an alphanumeric char
		when(conf.isMustEndWithAlpha()).thenReturn(true);
		try {
			super.enforce("password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password0.", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not end with an alphanumeric
		when(conf.isMustEndWithAlpha()).thenReturn(false);
		when(conf.isMustntEndWithAlpha()).thenReturn(true);
		try {
			super.enforce("password.", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void mustStartOrNotWithNonAlphaTest() {
		//Password must start with an non-alphanumeric char
		when(conf.isMustStartWithNonAlpha()).thenReturn(true);
		try {
			super.enforce(".Password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not start with an non-alphanumeric
		when(conf.isMustStartWithNonAlpha()).thenReturn(false);
		when(conf.isMustntStartWithNonAlpha()).thenReturn(true);
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce(".0password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
	
	@Test
	public void mustEndOrNotWithNonAlphaTest() {
		//Password must end with a non-alphanumeric char
		when(conf.isMustEndWithNonAlpha()).thenReturn(true);
		try {
			super.enforce("password0.", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed = false;
		try {
			super.enforce("password0", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed = true;
		}
		
		Assert.assertTrue(passed);
		
		//Password must not end with a non-alphanumeric
		when(conf.isMustEndWithNonAlpha()).thenReturn(false);
		when(conf.isMustntEndWithNonAlpha()).thenReturn(true);
		try {
			super.enforce("password", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				Assert.fail();
		}
		
		boolean passed2 = false;
		try {
			super.enforce("password0.", "domenico", new HashSet<String>());
		} catch (PasswordPolicyException e) {
				passed2 = true;
		}
		
		Assert.assertTrue(passed2);
	}
}
