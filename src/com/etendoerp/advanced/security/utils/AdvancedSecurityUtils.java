package com.etendoerp.advanced.security.utils;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.hibernate.criterion.Restrictions;
import org.openbravo.authentication.hashing.PasswordHash;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.data.UserPassword;

public class AdvancedSecurityUtils {

  private AdvancedSecurityUtils() {
  }

  public static User getUser(String userName) {
    OBCriteria<User> currentUserCriteria = OBDal.getInstance().createCriteria(User.class);
    currentUserCriteria.setMaxResults(1);
    currentUserCriteria.add(Restrictions.eq(User.PROPERTY_USERNAME, userName));
    currentUserCriteria.setFilterOnReadableClients(false);
    currentUserCriteria.setFilterOnReadableOrganization(false);
    currentUserCriteria.setFilterOnActive(true);
    return (User) currentUserCriteria.uniqueResult();
  }

  /**
   * @param lastPasswordUpdate Date of last password update
   * @param systemInfo Unique ad_system_info configuration
   * @return Password expiration deadline
   */
  public static Date getDateLimitToExpire(Date lastPasswordUpdate, SystemInformation systemInfo) {
    Calendar dateLimitToExpire = Calendar.getInstance();
    dateLimitToExpire.setTime(lastPasswordUpdate);
    dateLimitToExpire.add(Calendar.DAY_OF_WEEK, systemInfo.getEtasTimetochangePass().intValue());
    return dateLimitToExpire.getTime();
  }

  /**
   * @param dateLimitToExpire Password expiration deadline
   * @param inDays true if the difference in days is desired, otherwise in hours.
   * @return Difference in days (or hours) between the current date and the password change deadline.
   */
  public static long getDiffBetweenDateLimitAndNow(Date dateLimitToExpire, boolean inDays) {
    var diffBetweenDateLimitAndNow = dateLimitToExpire.getTime() - new Date().getTime();
    return inDays ? TimeUnit.MILLISECONDS.toDays(diffBetweenDateLimitAndNow) % 365 : TimeUnit.MILLISECONDS.toHours(
        diffBetweenDateLimitAndNow) % 24;
  }

  /**
   * Verify if the password entered has not been used in the user's password history.
   *
   * @param savedPasswords List of saved password from current user
   * @param newPwd New password to verify
   * @return True when list of saved passwords contains new password, otherwise, false.
   */
  public static boolean verifySavedPassword(List<String> savedPasswords, String newPwd) {
    for (String savedPassword : savedPasswords) {
      if (PasswordHash.matches(newPwd, savedPassword)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Retrieves the user's saved password history
   *
   * @param user Current User
   * @return User password history
   */
  public static List<String> getSavedPasswordFromUser(User user) {
    List<String> savedPasswordStr = new ArrayList<>();
    OBCriteria<UserPassword> userPasswordOBCriteria = OBDal.getInstance()
        .createCriteria(UserPassword.class);
    userPasswordOBCriteria.add(Restrictions.eq(UserPassword.PROPERTY_USER, user));
    var savedPassword = userPasswordOBCriteria.list();
    if (!savedPassword.isEmpty()) {
      for (UserPassword userPassword : savedPassword) {
        savedPasswordStr.add(userPassword.getSavedPassword());
      }
    }
    return savedPasswordStr;
  }
}
