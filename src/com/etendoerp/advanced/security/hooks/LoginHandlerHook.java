package com.etendoerp.advanced.security.hooks;

import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

public class LoginHandlerHook implements org.openbravo.base.util.LoginHandlerHook {

  private static final String SYSTEM_USER_ID = "100";

  private static final int DAYS_TO_REMEMBER = 7;

  @Override
  public OBError process(String userName, String action) {
    OBError passwordExpiredError = new OBError();
    try {
      User user = AdvancedSecurityUtils.getUser(userName);
      if (user != null) {
        final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
        final var daysToExpirePassword = AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(user);

        /* Check if the system is configured to show expired password message, the user is not null,
        and the password is near to expire */
        if (systemInfo.isEtasShowExpiredMsg() && !StringUtils.equals(SYSTEM_USER_ID, user.getId()) &&
            isPasswordNearToExpire(user.getLastPasswordUpdate(), daysToExpirePassword)) {
          passwordExpiredError.setType("Warning");
          passwordExpiredError.setTitle(OBMessageUtils.messageBD("ETAS_PasswordNearToExpTittle"));
          final Date dateLimitToExpire = AdvancedSecurityUtils.getDateLimitToExpire(user.getLastPasswordUpdate(),
              daysToExpirePassword);
          long timeDiff = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, true);
          String message = "ETAS_PasswordNearToExp";
          // This case implies the difference in days = 0, therefore, it is necessary to report the amount in hours.
          if (timeDiff == 0) {
            message = "ETAS_PasswordNearToExpHour";
            timeDiff = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, false);
          }
          message = String.format(OBMessageUtils.messageBD(message), timeDiff);
          passwordExpiredError.setMessage(message);
          return passwordExpiredError;
        }
      }
    } catch (Exception e) {
      passwordExpiredError.setType("Error");
      passwordExpiredError.setMessage(e.getMessage());
      return passwordExpiredError;
    }
    return null;
  }

  private boolean isPasswordNearToExpire(Date lastPasswordUpdate, String daysToExpirePassword) {
    Date dateLimitToExpire = AdvancedSecurityUtils.getDateLimitToExpire(lastPasswordUpdate, daysToExpirePassword);
    final long daysDifference = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, true);
    return (daysDifference <= DAYS_TO_REMEMBER);
  }

}
