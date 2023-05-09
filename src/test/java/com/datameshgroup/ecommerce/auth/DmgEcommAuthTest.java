package com.datameshgroup.ecommerce.auth;

import junit.framework.TestCase;

public class DmgEcommAuthTest extends TestCase {

    public void testCreateAuthToken() {
        DmgEcommAuth auth = new DmgEcommAuth("testApiId", "testAPIKEY");

        String token = auth.createAuthToken("/order_token", "{ \"order_request\": { \"details_format\": \"details\", \"order_details\": { \"order\": { \"service_id\": \"63586114-3c20-4981-a906-79253c4694d4\", \"order_amount\": { \"value\": 4000, \"currency\": { \"name\": \"Indian Rupees\", \"currency_code\": \"INR\", \"decimal_places\": 2, \"separator\": true, \"symbol\": \"₹\" } }, \"customer\": { \"entity_type\": \"person\", \"details_format\": \"details\", \"entity_details\": { \"name\": { \"full_name\": \"Company Name\" }, \"email\": \"companyinfo@email.com\", \"phone_number\": { \"type\": \"mobile\", \"details\": { \"unformatted_number\": \"+913852543512\" } } } }, \"orchestration_id\": \"bdc731ca-192b-423e-a2b8-bde0b8b477d2\" } } } }");

        assert token != null;
        System.out.println(token);
    }

    public void testBytesToHexString() {
        byte[] bytes = new byte[]{0x00, 0x01, 0x02, 0x03};
        String hexString = DmgEcommAuth.bytesToHexString(bytes);
        assertEquals("00010203", hexString);
    }
}