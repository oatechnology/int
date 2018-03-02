package com.interactivebrokers.webtradingapi.client.model;

public class Message {
	
	private byte[] ls;
	private String accessToken;
	
	
	
	public Message() {
		// TODO Auto-generated constructor stub
	}
	
	public Message(byte[] ls, String accessToken) {
		super();
		this.ls = ls;
		this.accessToken = accessToken;
	}

	public byte[] getLs() {
		return ls;
	}
	public void setLs(byte[] ls) {
		this.ls = ls;
	}
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	
	
 }
