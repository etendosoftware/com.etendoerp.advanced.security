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
    User user = AdvancedSecurityUtils.getUser(userName);
    final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");

    /* Check if the system is configured to show expired password message, the user is not null,
    and the password is near to expire */
    if (systemInfo.isEasEnablepassExpiration() && systemInfo.isEasShowExpiredMsg() && user != null
        && !StringUtils.equals(SYSTEM_USER_ID, user.getId()) &&
        isPasswordNearToExpire(user.getLastPasswordUpdate(), systemInfo)) {
      OBError passwordExpiredError = new OBError();
      passwordExpiredError.setType("Warning");
      passwordExpiredError.setTitle(OBMessageUtils.messageBD("EAS_PasswordNearToExpTittle"));
      final Date dateLimitToExpire = AdvancedSecurityUtils.getDateLimitToExpire(user.getLastPasswordUpdate(),
          systemInfo);
      long timeDiff = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, true);
      String message = "EAS_PasswordNearToExp";
      // This case implies the difference in days = 0, therefore, it is necessary to report the amount in hours.
      if (timeDiff == 0) {
        message = "EAS_PasswordNearToExpHour";
        timeDiff = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, false);
      }
      message = String.format(OBMessageUtils.messageBD(message), timeDiff);
      passwordExpiredError.setMessage(message);
      return passwordExpiredError;
    }
    return null;
  }

  private boolean isPasswordNearToExpire(Date lastPasswordUpdate, SystemInformation systemInfo) {
    Date dateLimitToExpire = AdvancedSecurityUtils.getDateLimitToExpire(lastPasswordUpdate, systemInfo);
    final long daysDifference = AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(dateLimitToExpire, true);
    return (daysDifference <= DAYS_TO_REMEMBER);
  }

}
