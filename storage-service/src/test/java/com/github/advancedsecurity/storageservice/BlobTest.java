package com.github.advancedsecurity.storageservice;

import com.github.advancedsecurity.storageservice.models.Blob;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class BlobTest {

    @Test
    void constructorStoresMimeType() {
        byte[] data = "hello".getBytes();
        Blob blob = new Blob("image/png", data);
        assertEquals("image/png", blob.getMimeType());
    }

    @Test
    void constructorBase64EncodesData() {
        byte[] data = "hello world".getBytes();
        Blob blob = new Blob("text/plain", data);
        String expected = Base64.getEncoder().encodeToString(data);
        assertEquals(expected, blob.getData());
    }

    @Test
    void emptyByteArrayIsEncodedAsEmptyString() {
        Blob blob = new Blob("application/octet-stream", new byte[0]);
        assertEquals("", blob.getData());
    }

    @Test
    void getMimeTypeReturnsCorrectType() {
        Blob blob = new Blob("image/jpeg", new byte[]{1, 2, 3});
        assertEquals("image/jpeg", blob.getMimeType());
    }

    @Test
    void getDataReturnsSameEncodedValueEachTime() {
        byte[] data = "consistent data".getBytes();
        Blob blob = new Blob("text/plain", data);
        assertEquals(blob.getData(), blob.getData());
    }
}
