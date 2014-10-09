package com.jdriven.stateless.security;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = StatelessAuthentication.class)
@WebAppConfiguration
@IntegrationTest("server.port:8181")
public class StatelessAuthenticationIntegrationTest {

	// GET RESOURCES

	@Test
	public void testRoot_Get_Anonymous() {
		doAnonymousExchange(HttpMethod.GET, "/");
	}

	@Test
	public void testResource_Get_Anonymous() {
		doAnonymousExchange(HttpMethod.GET, "/resources/js/controllers.js");
	}

	// CHANGE OWN USER PASSWORD

	@Test(expected = HttpClientErrorException.class)
	public void testUserApi_Change_Password_AsAnonymous() {
		doAnonymousExchange(HttpMethod.POST, "/api/users/current?_method=PATCH",
				"{\"password\":\"user\", \"newPassword\":\"test\"}");
	}

	@Test
	public void testUserApi_Change_Password_AsUser() throws JsonProcessingException {
		doAuthenticatedExchange("user", HttpMethod.POST, "/api/users/current?_method=PATCH",
				"{\"password\":\"user\", \"newPassword\":\"test\"}", "user");

		doAuthenticatedExchange("user", HttpMethod.POST, "/api/users/current?_method=PATCH",
				"{\"password\":\"test\", \"newPassword\":\"user\"}", "test");
	}

	// GET OWN USER DETAILS

	@Test
	public void testUserApi_Get_Anonymous() {
		final String result = doAnonymousExchange(HttpMethod.GET, "/api/users/current");
		assertTrue(result.contains("\"username\":\"anonymousUser\""));
		assertTrue(result.contains("\"roles\":[]"));
	}

	@Test
	public void testUserApi_Get_User() {
		final String result = doAuthenticatedExchange("user", HttpMethod.GET, "/api/users/current");
		assertTrue(result.contains("\"username\":\"user\""));
		assertTrue(result.contains("\"roles\":[\"USER\"]"));
	}

	@Test
	public void testUserApi_Get_Admin() {
		final String result = doAuthenticatedExchange("admin", HttpMethod.GET, "/api/users/current");
		assertTrue(result.contains("\"username\":\"admin\""));
		assertTrue(result.contains("\"roles\":[\"ADMIN\"]"));
	}

	// GET ALL USER DETAILS (ADMIN FUNCTIONALITY)

	@Test(expected = HttpClientErrorException.class)
	public void testAdminApi_Get_Users_AsAnonymous() {
		doAnonymousExchange(HttpMethod.GET, "/admin/api/users");
	}

	@Test(expected = HttpClientErrorException.class)
	public void testAdminApi_Get_Users_AsUser() {
		doAuthenticatedExchange("user", HttpMethod.GET, "/admin/api/users");
	}

	@Test
	public void testAdminApi_Get_Users_AsAdmin() {
		final String result = doAuthenticatedExchange("admin", HttpMethod.GET, "/admin/api/users");
		assertEquals("[{\"id\":10,\"username\":\"admin\",\"expires\":0,\"roles\":[\"ADMIN\"]}"
				+ ",{\"id\":11,\"username\":\"user\",\"expires\":0,\"roles\":[\"USER\"]}]", result);
	}

	// GRANT A ROLE TO A USER (ADMIN FUNCTIONALITY)

	@Test(expected = HttpClientErrorException.class)
	public void testAdminApi_GrantRole_AsAnonymous() {
		doAnonymousExchange(HttpMethod.POST, "/admin/api/users/11/grant/role/ADMIN");
	}

	@Test(expected = HttpClientErrorException.class)
	public void testAdminApi_GrantRole_AsUser() {
		doAuthenticatedExchange("user", HttpMethod.POST, "/admin/api/users/11/grant/role/ADMIN");
	}

	@Test
	public void testAdminApi_GrantRole_AsAdmin() {
		doAuthenticatedExchange("admin", HttpMethod.POST, "/admin/api/users/11/grant/role/ADMIN");
		doAuthenticatedExchange("admin", HttpMethod.POST, "/admin/api/users/11/revoke/role/ADMIN");
	}

	private String doAnonymousExchange(final HttpMethod method, final String path) {
		return doAnonymousExchange(method, path, null);
	}

	private String doAnonymousExchange(final HttpMethod method, final String path, String request) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> testRequest = new HttpEntity<>(request, httpHeaders);
		HttpEntity<String> testResponse = restTemplate.exchange("http://localhost:8181/" + path, method, testRequest,
				String.class);
		return testResponse.getBody();
	}

	private String doAuthenticatedExchange(final String user, final HttpMethod method, final String path) {
		return doAuthenticatedExchange(user, method, path, null, user);
	}

	private String doAuthenticatedExchange(final String user, final HttpMethod method, final String path,
			String request, String password) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> login = new HttpEntity<>(
				"{\"username\":\"" + user + "\",\"password\":\"" + password + "\"}", httpHeaders);
		ResponseEntity<Void> results = restTemplate.postForEntity("http://localhost:8181/api/login", login, Void.class);

		httpHeaders.add("X-AUTH-TOKEN", results.getHeaders().getFirst("X-AUTH-TOKEN"));
		HttpEntity<String> testRequest = new HttpEntity<>(request, httpHeaders);
		HttpEntity<String> testResponse = restTemplate.exchange("http://localhost:8181/" + path, method, testRequest,
				String.class);
		return testResponse.getBody();
	}
}
