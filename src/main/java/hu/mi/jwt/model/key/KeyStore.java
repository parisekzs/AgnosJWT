/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.jwt.model.key;

import java.util.Map;

/**
 *
 * @author parisek
 */
public interface KeyStore {
  
    public Map<String, String> getMap(String mapName);
}
