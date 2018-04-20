// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package io.qaxh.hash;

import com.google.appinventor.components.runtime.Component;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;

import java.util.Formatter;
import java.security.Security;
import java.security.MessageDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.common.YaVersion;
import com.google.appinventor.components.runtime.util.ErrorMessages;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import java.io.File;
import java.util.Date;

/**
 * Provides access to basic hash functions
 *
 *
 */
@DesignerComponent(version = YaVersion.QAXH_HASH_COMPONENT_VERSION,
   description = "A component return the hash of a string.",
   category = ComponentCategory.EXTENSION,
   nonVisible = true,
   iconName = "aiwebres/hash.png")
@SimpleObject(external=true)
@UsesLibraries(libraries = "bcprov-jdk15on-157.jar")
public class QAXH_Hash extends AndroidNonvisibleComponent implements Component {
  
  private static final String LOG_TAG = "QaxhHashComponent";

  /**
   * Creates a QAXH_Hash component.
   *
   * @param container container, component will be placed in
   */
  public QAXH_Hash(ComponentContainer container) {
     super(container.$form());
   //Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Computes SHA-1
   */
  @SimpleFunction(
		  description = "Computes the SHA-1 of the string parameter.")
		  public String sha1(String message){
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA1");
    } catch (Exception e) {
      Log.e(LOG_TAG, "Exception getting SHA1 Instance", e);
      return "";
    }
    md.update(message.getBytes());
    byte [] result = md.digest();
    StringBuffer sb = new StringBuffer(result.length * 2);
    Formatter formatter = new Formatter(sb);
    for (byte b : result) {
      formatter.format("%02x", b);
    }
    Log.d(LOG_TAG, "Message = " + message);
    Log.d(LOG_TAG, "Code = " + sb.toString());
    return sb.toString();
  }

 /**
  * Computes SHA-256
  */
  @SimpleFunction(
      description = "Computes the SHA-256 of the string parameter.")
  public String sha256(String message) {
   MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA-256");
    } catch (Exception e) {
      Log.e(LOG_TAG, "Exception getting SHA-256 Instance", e);
      return "";
    }
    md.update(message.getBytes());
    byte [] result = md.digest();
    StringBuffer sb = new StringBuffer(result.length * 2);
    Formatter formatter = new Formatter(sb);
    for (byte b : result) {
      formatter.format("%02x", b);
    }
    Log.d(LOG_TAG, "Message = " + message);
    Log.d(LOG_TAG, "Code = " + sb.toString());
    return sb.toString();
  }

 /**
  * Computes SHA-3
  */
  @SimpleFunction(
      description = "Computes the SHA-3 of the string parameter.")
  public String sha3(String message) {
    SHA3.DigestSHA3 md = new SHA3.DigestSHA3(256);
    md.update(message.getBytes());
    byte [] result = md.digest();
    StringBuffer sb = new StringBuffer(result.length * 2);
    Formatter formatter = new Formatter(sb);
    for (byte b : result) {
      formatter.format("%02x", b);
    }
    Log.d(LOG_TAG, "Message = " + message);
    Log.d(LOG_TAG, "Code = " + sb.toString());
    return sb.toString();
  }

 /**
  * Computes Keccak-256
  */
 
  @SimpleFunction(
    description = "Computes the Keccak-256 of the string parameter.")
    public String keccak(String message) {
    Keccak.DigestKeccak md = new Keccak.DigestKeccak(256);
    md.update(message.getBytes());
    byte [] result = md.digest();
    StringBuffer sb = new StringBuffer(result.length * 2);
    Formatter formatter = new Formatter(sb);
    for (byte b : result) {
      formatter.format("%02x", b);
    }
    Log.d(LOG_TAG, "Message = " + message);
    Log.d(LOG_TAG, "Code = " + sb.toString());
    return sb.toString();
  }
}
