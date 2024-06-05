

---

## Token Authentication Middleware Process

The `TokenAuthenticationMiddleware` is a crucial component of our authentication system, managing the validation of JWT tokens for every incoming request. This middleware differentiates between valid and invalid (including expired) tokens, dictating the flow of request processing based on this distinction.

### Handling Invalid or Expired Tokens

When a request contains an invalid or expired JWT token, the middleware intercepts and halts further processing of the request, immediately returning an error response. This ensures unauthorized requests are promptly identified and denied, enhancing the security of the application.

**Process Overview:**

1. **Token Verification**: Each incoming request is checked for the presence of an `accessToken` in the cookies. This token is then validated against the application's secret key.
2. **Error Response**: If the token is found to be invalid or expired (detected through `jwt.ExpiredSignatureError` or `jwt.InvalidTokenError`), the middleware logs the error and returns a `JsonResponse` indicating the specific authentication failure.
3. **Immediate Halt**: This response is returned directly to the client, preventing any further processing of the request by subsequent middleware or the targeted view.

### Processing Valid Tokens

For requests accompanied by a valid JWT token, the middleware authenticates the request by setting the user in the request context, allowing the request to proceed to the application's secured areas.

**Process Overview:**

1. **Token Decoding**: Upon detecting a valid `accessToken`, the middleware decodes the token to extract the user's identity, specifically the user ID.
2. **User Retrieval**: It then retrieves the corresponding user from the database using the extracted user ID.
3. **Request Authentication**: The retrieved user object is attached to `request.user`, marking the request as authenticated. This action also facilitates user-specific request processing down the line.
4. **Forwarding the Request**: Finally, the request is forwarded to the next middleware or directly to the view if there are no further middlewares. At this point, the request is considered authenticated, and the user is granted access to the protected resources.

