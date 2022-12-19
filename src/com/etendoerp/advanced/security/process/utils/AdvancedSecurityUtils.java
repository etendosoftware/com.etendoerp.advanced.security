package com.etendoerp.advanced.security.process.utils;

import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.hibernate.criterion.Restrictions;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

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
    dateLimitToExpire.add(Calendar.DAY_OF_WEEK, systemInfo.getEasTimetochangePass().intValue());
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
}
