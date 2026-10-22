package me.zhyd.oauth.utils;

import java.util.UUID;

import org.junit.jupiter.api.Test;

public class UuidUtilsTest {

    @Test
    public void getUUID() {
    		long start = System.currentTimeMillis();
    		for(int i=0;i<=1000000;i++) {
	        String uuid = UuidUtils.getUUID();
	        System.out.println(uuid);
    		}
    		System.out.println("cost "+(System.currentTimeMillis() - start));
    }
    
    @Test
    public void getJdkUUID() {
    	long start = System.currentTimeMillis();
		for(int i=0;i<=1000000;i++) {
        String uuid = UUID.randomUUID().toString().toLowerCase().replace("-", "");
        System.out.println(uuid);
		}
		System.out.println("cost "+(System.currentTimeMillis() - start));
    }
}
