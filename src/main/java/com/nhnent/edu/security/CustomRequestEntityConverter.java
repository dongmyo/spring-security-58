package com.nhnent.edu.security;

import java.net.URI;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class CustomRequestEntityConverter
    implements Converter<OAuth2UserRequest, RequestEntity<?>> {
    @Override
    public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();

        URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails()
                .getUserInfoEndpoint().getUri())
            .build()
            .toUri();

        // headers.
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
        requestHeaders.add(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue());

        // body.
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
        requestBody.add(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue());

        return new RequestEntity<>(requestBody, requestHeaders, HttpMethod.POST, uri);
    }

}
