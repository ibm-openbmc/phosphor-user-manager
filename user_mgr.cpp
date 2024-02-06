/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "config.h"

#include "user_mgr.hpp"

#include "file.hpp"
#include "shadowlock.hpp"
#include "users.hpp"

#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <boost/algorithm/string/split.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <algorithm>
#include <ctime>
#include <fstream>
#include <numeric>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace phosphor
{
namespace user
{

static constexpr const char* passwdFileName = "/etc/passwd";
static constexpr size_t ipmiMaxUserNameLen = 16;
static constexpr size_t systemMaxUserNameLen = 30;
static constexpr const char* grpSsh = "ssh";
static constexpr int success = 0;
static constexpr int failure = -1;

// pam modules related
static constexpr const char* pamFaillock = "pam_faillock.so";
static constexpr const char* pamPWQuality = "pam_pwquality.so";
static constexpr const char* pamPWHistory = "pam_pwhistory.so";
static constexpr const char* minPasswdLenProp = "minlen";
static constexpr const char* remOldPasswdCount = "remember";
static constexpr const char* maxFailedAttempt = "deny";
static constexpr const char* unlockTimeout = "unlock_time";
static constexpr const char* defaultPamPasswdConfigFile =
    "/etc/pam.d/common-password";
static constexpr const char* faillockConfigFile = "/etc/security/faillock.conf";
static constexpr const char* pwQualityConfigFile =
    "/etc/security/pwquality.conf";

// Object Manager related
static constexpr const char* ldapMgrObjBasePath =
    "/xyz/openbmc_project/user/ldap";

// Object Mapper related
static constexpr const char* objMapperService =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* objMapperPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* objMapperInterface =
    "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using UserNameExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameExists;
using UserNameDoesNotExist =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameDoesNotExist;
using UserNameGroupFail =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameGroupFail;
using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;

using Argument = xyz::openbmc_project::Common::InvalidArgument;

std::string getCSVFromVector(std::span<const std::string> vec)
{
    if (vec.empty())
    {
        return "";
    }
    return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                           [](std::string&& val, std::string_view element) {
                               val += ',';
                               val += element;
                               return val;
                           });
}

bool removeStringFromCSV(std::string& csvStr, const std::string& delStr)
{
    std::string::size_type delStrPos = csvStr.find(delStr);
    if (delStrPos != std::string::npos)
    {
        // need to also delete the comma char
        if (delStrPos == 0)
        {
            csvStr.erase(delStrPos, delStr.size() + 1);
        }
        else
        {
            csvStr.erase(delStrPos - 1, delStr.size() + 1);
        }
        return true;
    }
    return false;
}

bool UserMgr::isUserExist(const std::string& userName)
{
    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (usersList.find(userName) == usersList.end())
    {
        return false;
    }
    return true;
}

void UserMgr::throwForUserDoesNotExist(const std::string& userName)
{
    if (!isUserExist(userName))
    {
        log<level::ERR>("User does not exist",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameDoesNotExist>();
    }
}

void UserMgr::throwForUserExists(const std::string& userName)
{
    if (isUserExist(userName))
    {
        log<level::ERR>("User already exists",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameExists>();
    }
}

void UserMgr::throwForUserNameConstraints(
    const std::string& userName, const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (userName.length() > ipmiMaxUserNameLen)
        {
            log<level::ERR>("IPMI user name length limitation",
                            entry("SIZE=%d", userName.length()));
            elog<UserNameGroupFail>(
                xyz::openbmc_project::User::Common::UserNameGroupFail::REASON(
                    "IPMI length"));
        }
    }
    if (userName.length() > systemMaxUserNameLen)
    {
        log<level::ERR>("User name length limitation",
                        entry("SIZE=%d", userName.length()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid length"));
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        log<level::ERR>("Invalid user name",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid data"));
    }
}

void UserMgr::throwForMaxGrpUserCount(
    const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (getIpmiUsersCount() >= ipmiMaxUsers)
        {
            log<level::ERR>("IPMI user limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "ipmi user count reached"));
        }
    }
    else
    {
        if (usersList.size() > 0 && (usersList.size() >= maxSystemUsers))
        {
            log<level::ERR>("Non-ipmi User limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "Non-ipmi user count reached"));
        }
    }
    return;
}

void UserMgr::throwForInvalidPrivilege(const std::string& priv)
{
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }
}

void UserMgr::throwForInvalidGroups(const std::vector<std::string>& groupNames)
{
    for (auto& group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) ==
            groupsMgr.end())
        {
            log<level::ERR>("Invalid Group Name listed");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GroupName"),
                                  Argument::ARGUMENT_VALUE(group.c_str()));
        }
    }
}

/* Notes for restricted priv-operator role:
 *
 * The priv-operator role is restricted so you cannot create an operator user
 * or change an existing user to have the operator role.  However, if there
 * happens to be a user with the operator role, you are allowed to rename or
 * delete that user, or change them away from the operator role.
 */
void UserMgr::throwForRestrictedPrivilegeRole(const std::string& priv)
{
    if ((priv == "priv-oemibmserviceagent") || (priv == "priv-operator"))
    {
        log<level::ERR>("Restricted role");
        elog<InternalFailure>();
    }
}

void UserMgr::throwForRestrictedUserPrivilegeRole(const std::string& userName)
{
    const std::string priv = usersList[userName].get()->userPrivilege();
    if (priv == "priv-oemibmserviceagent")
    {
        log<level::ERR>("User has restricted role");
        elog<InternalFailure>();
    }
}

void UserMgr::createUser(std::string userName,
                         std::vector<std::string> groupNames, std::string priv,
                         bool enabled)
{
    throwForInvalidPrivilege(priv);
    throwForRestrictedPrivilegeRole(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserExists(userName);
    throwForUserNameConstraints(userName, groupNames);
    throwForMaxGrpUserCount(groupNames);

    std::string groups = getCSVFromVector(groupNames);

    // The "ssh" phosphor-privilege group controls access to the host console
    // via SSH port 2200 and has a special implementation.
    // In the OpenBMC community project:
    //   A. It allows access to the BMC's SSH interfaces
    //       - SSH port 22 reaches the BMC's command shell.
    //       - SSH port 2200 reaches the host console.
    //   B. It is enforced by two mechanisms:
    //       1. The SSH dropbear server command uses the -G priv-admin argument
    //          to restrict SSH access to users who are in the priv-admin Linux
    //          group.
    //       2. The Linux user's login shell was set to /bin/sh (when "ssh" was
    //          specified) or /bin/nologin (when "ssh" is not specified).
    //          Having loginShell=/bin/sh is required to be able to get in
    //          through the SSH interface.  The condition (loginShell==/bin/sh)
    //          is equivalent to being in the "ssh" privilege-group.
    //       Note there is no "ssh" Linux group.
    // For p10bmc:
    //   A. Additionally:
    //       - SSH port 2201 to reaches the hypervisor console (PHYP).
    //   B. We created three new Linux groups to control access to the SSH
    //         destinations:
    //       - SSH port 22 is controlled by membership in "bmcshellaccess".
    //         Only the special service user should be in this group.
    //       - SSH port 2200 is controlled by membership in "hostconsoleaccess"
    //         All users (including the service user) should be in this group.
    //       - SSH port 2201 is controlled by membership in the
    //         "hypervisorconsoleaccess" group.
    //         Only the special service user should be in this group.
    //   The special handling in this code when the user is in the "ssh" group
    //   (represented here as sshRequested):
    //    1. Add the user to the hostconsoleaccess Linux group.
    //    2. Set the user's login shell (as /bin/sh).
    //   Note: No special code is needed to handle the special "service" user
    //         because priv-oemibmserviceagent is a restricted role which means
    //         the service agent's groups cannot be changed.
    //   It remains up the BMC administrator to give "ssh" access to whichever
    //   users they want (for example, to admin users).
    bool sshRequested = removeStringFromCSV(groups, grpSsh);
    if (sshRequested)
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += "hostconsoleaccess";
    }

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserAdd(userName.c_str(), groups.c_str(), sshRequested, enabled);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Unable to create new user");
        elog<InternalFailure>();
    }

    // Add the users object before sending out the signal
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= userName;
    std::string userObj(tempObjPath);
    std::sort(groupNames.begin(), groupNames.end());
    usersList.emplace(
        userName, std::make_unique<phosphor::user::Users>(
                      bus, userObj.c_str(), groupNames, priv, enabled, *this));

    log<level::INFO>("User created successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::deleteUser(std::string userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    throwForRestrictedUserPrivilegeRole(userName);
    try
    {
        // Clear user fail records
        executeUserClearFailRecords(userName.c_str());

        executeUserDelete(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("User delete failed",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InternalFailure>();
    }

    usersList.erase(userName);

    log<level::INFO>("User deleted successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::renameUser(std::string userName, std::string newUserName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    throwForUserExists(newUserName);
    throwForUserNameConstraints(newUserName,
                                usersList[userName].get()->userGroups());
    throwForRestrictedUserPrivilegeRole(userName);
    try
    {
        executeUserRename(userName.c_str(), newUserName.c_str());
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("User rename failed",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InternalFailure>();
    }
    const auto& user = usersList[userName];
    std::string priv = user.get()->userPrivilege();
    std::vector<std::string> groupNames = user.get()->userGroups();
    bool enabled = user.get()->userEnabled();
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= newUserName;
    std::string newUserObj(tempObjPath);
    // Special group 'ipmi' needs a way to identify user renamed, in order to
    // update encrypted password. It can't rely only on InterfacesRemoved &
    // InterfacesAdded. So first send out userRenamed signal.
    this->userRenamed(userName, newUserName);
    usersList.erase(userName);
    usersList.emplace(newUserName, std::make_unique<phosphor::user::Users>(
                                       bus, newUserObj.c_str(), groupNames,
                                       priv, enabled, *this));
    return;
}

void UserMgr::updateGroupsAndPriv(const std::string& userName,
                                  std::vector<std::string> groupNames,
                                  const std::string& priv)
{
    throwForInvalidPrivilege(priv);
    throwForRestrictedPrivilegeRole(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    throwForRestrictedUserPrivilegeRole(userName);
    const std::vector<std::string>& oldGroupNames =
        usersList[userName].get()->userGroups();
    std::vector<std::string> groupDiff;
    // Note: already dealing with sorted group lists.
    std::set_symmetric_difference(oldGroupNames.begin(), oldGroupNames.end(),
                                  groupNames.begin(), groupNames.end(),
                                  std::back_inserter(groupDiff));
    if (std::find(groupDiff.begin(), groupDiff.end(), "ipmi") !=
        groupDiff.end())
    {
        throwForUserNameConstraints(userName, groupNames);
        throwForMaxGrpUserCount(groupNames);
    }

    std::string groups = getCSVFromVector(groupNames);
    // The "ssh" phosphor privilege group is handled specially
    bool sshRequested = removeStringFromCSV(groups, grpSsh);
    if (sshRequested)
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += "hostconsoleaccess";
    }

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserModify(userName.c_str(), groups.c_str(), sshRequested);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Unable to modify user privilege / groups");
        elog<InternalFailure>();
    }

    log<level::INFO>("User groups / privilege updated successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    std::sort(groupNames.begin(), groupNames.end());
    usersList[userName]->setUserGroups(groupNames);
    usersList[userName]->setUserPrivilege(priv);
    return;
}

uint8_t UserMgr::minPasswordLength(uint8_t value)
{
    if (value == AccountPolicyIface::minPasswordLength())
    {
        return value;
    }
    if (value < minPasswdLength)
    {
        log<level::ERR>(("Attempting to set minPasswordLength to less than " +
                         std::to_string(minPasswdLength))
                            .c_str(),
                        entry("SIZE=%d", value));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("minPasswordLength"),
            Argument::ARGUMENT_VALUE(std::to_string(value).c_str()));
    }
    if (setPamModuleArgValue(pamPWQuality, minPasswdLenProp,
                             std::to_string(value)) != success)
    {
        log<level::ERR>("Unable to set minPasswordLength");
        elog<InternalFailure>();
    }
    return AccountPolicyIface::minPasswordLength(value);
}

uint8_t UserMgr::rememberOldPasswordTimes(uint8_t value)
{
    if (value == AccountPolicyIface::rememberOldPasswordTimes())
    {
        return value;
    }
    if (setPamModuleArgValue(pamPWHistory, remOldPasswdCount,
                             std::to_string(value)) != success)
    {
        log<level::ERR>("Unable to set rememberOldPasswordTimes");
        elog<InternalFailure>();
    }
    return AccountPolicyIface::rememberOldPasswordTimes(value);
}

uint16_t UserMgr::maxLoginAttemptBeforeLockout(uint16_t value)
{
    if (value == AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return value;
    }
    if (setPamModuleArgValue(pamFaillock, maxFailedAttempt,
                             std::to_string(value)) != success)
    {
        log<level::ERR>("Unable to set maxLoginAttemptBeforeLockout");
        elog<InternalFailure>();
    }
    return AccountPolicyIface::maxLoginAttemptBeforeLockout(value);
}

uint32_t UserMgr::accountUnlockTimeout(uint32_t value)
{
    if (value == AccountPolicyIface::accountUnlockTimeout())
    {
        return value;
    }
    if (setPamModuleArgValue(pamFaillock, unlockTimeout,
                             std::to_string(value)) != success)
    {
        log<level::ERR>("Unable to set accountUnlockTimeout");
        elog<InternalFailure>();
    }
    return AccountPolicyIface::accountUnlockTimeout(value);
}

int UserMgr::getPamModuleArgValue(const std::string& moduleName,
                                  const std::string& argName,
                                  std::string& argValue)
{
    std::string fileName;
    bool simpleConfigFile = false;
    if (moduleName == pamFaillock)
    {
        fileName = faillockConfigFile;
        simpleConfigFile = true;
    }
    else if (moduleName == pamPWQuality)
    {
        fileName = pwQualityConfigFile;
        simpleConfigFile = true;
    }
    else
    {
        fileName = pamPasswdConfigFile;
    }
    std::ifstream fileToRead(fileName, std::ios::in);
    if (!fileToRead.is_open())
    {
        log<level::ERR>("Failed to open pam configuration file",
                        entry("FILE_NAME=%s", fileName.c_str()));
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if (simpleConfigFile || (line.find(moduleName) != std::string::npos))
        {
            if ((startPos = line.find(argSearch)) != std::string::npos)
            {
                if ((endPos = line.find(' ', startPos)) == std::string::npos)
                {
                    endPos = line.size();
                }
                startPos += argSearch.size();
                argValue = line.substr(startPos, endPos - startPos);
                return success;
            }
        }
    }
    return failure;
}

int UserMgr::setPamModuleArgValue(const std::string& moduleName,
                                  const std::string& argName,
                                  const std::string& argValue)
{
    std::string fileName;
    bool simpleConfigFile = false;
    if (moduleName == pamFaillock)
    {
        fileName = faillockConfigFile;
        simpleConfigFile = true;
    }
    else if (moduleName == pamPWQuality)
    {
        fileName = pwQualityConfigFile;
        simpleConfigFile = true;
    }
    else
    {
        fileName = pamPasswdConfigFile;
    }
    std::string tmpFileName = fileName + "_tmp";
    std::ifstream fileToRead(fileName, std::ios::in);
    std::ofstream fileToWrite(tmpFileName, std::ios::out);
    if (!fileToRead.is_open() || !fileToWrite.is_open())
    {
        log<level::ERR>("Failed to open pam configuration /tmp file",
                        entry("FILE_NAME=%s", fileName.c_str()));
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    bool found = false;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                fileToWrite << line << std::endl;
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if (simpleConfigFile || (line.find(moduleName) != std::string::npos))
        {
            if ((startPos = line.find(argSearch)) != std::string::npos)
            {
                if ((endPos = line.find(' ', startPos)) == std::string::npos)
                {
                    endPos = line.size();
                }
                startPos += argSearch.size();
                fileToWrite << line.substr(0, startPos) << argValue
                            << line.substr(endPos, line.size() - endPos)
                            << std::endl;
                found = true;
                continue;
            }
        }
        fileToWrite << line << std::endl;
    }
    fileToWrite.close();
    fileToRead.close();
    if (found)
    {
        if (std::rename(tmpFileName.c_str(), fileName.c_str()) == 0)
        {
            return success;
        }
    }
    return failure;
}

void UserMgr::userEnable(const std::string& userName, bool enabled)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    // Note: Allowed to enable and disable users with restricted role
    try
    {
        executeUserModifyUserEnable(userName.c_str(), enabled);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Unable to modify user enabled state");
        elog<InternalFailure>();
    }

    log<level::INFO>("User enabled/disabled state updated successfully",
                     entry("USER_NAME=%s", userName.c_str()),
                     entry("ENABLED=%d", enabled));
    usersList[userName]->setUserEnabled(enabled);
    return;
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    if (AccountPolicyIface::maxLoginAttemptBeforeLockout() == 0)
    {
        return false;
    }

    std::vector<std::string> output;
    try
    {
        output = getFailedAttempt(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Unable to read login failure counter");
        elog<InternalFailure>();
    }

    // Expected output:
    // If user is not known to faillock, output is empty.
    // If user is known to faillock, output is two header lines followed by zero
    // or more records:
    // > {userName}:
    // > "When        Type    Source          Valid"
    // > ${timestamp} ${type} {RHOST,TTY,SVC} {V,I}
    //
    // If there is an error, the output is a single line like this:
    // /usr/sbin/faillock: Error clearing the tally file for {user}:{output from
    // perror}
    // Example: /usr/sbin/faillock: Error opening the tally file for admin:Not
    // a directory

    int failedAttempts = 0;
    if (output.empty())
    {
        failedAttempts = 0;
    }
    else if (output.size() < 2)
    {
        log<level::ERR>("faillock resulted in error",
                        entry("USER=%s", userName.c_str()));
        if (output.size() >= 1)
        {
            log<level::ERR>("faillock error message",
                            entry("ERROR=%s", output[0].c_str()));
        }
        elog<InternalFailure>();
    }
    else
    {
        failedAttempts = output.size() - 2;
    }
    if (AccountPolicyIface::maxLoginAttemptBeforeLockout() != 0 &&
        failedAttempts >= AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return true; // User account password is locked
    }
    return false;    // User account password is un-locked
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName,
                                         const bool& value)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    // Note: Allowed to unlock password of users with restricted role
    std::vector<std::string> output;
    if (value == true)
    {
        return userLockedForFailedAttempt(userName);
    }

    output =
        executeCmd("/usr/sbin/faillock", "--user", userName.c_str(), "--reset");

    if (!output.empty() && output[0].find("Error") != std::string::npos)
    {
        log<level::ERR>("faillock reset resulted in error",
                        entry("USER=%s", userName.c_str()),
                        entry("OUTPUT=%s", output[0].c_str()));
        elog<InternalFailure>();
    }
    return userLockedForFailedAttempt(userName);
}

bool UserMgr::userPasswordExpired(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    struct spwd spwd
    {};
    struct spwd* spwdPtr = nullptr;
    auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen < -1)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }
    std::vector<char> buffer(buflen);
    auto status =
        getspnam_r(userName.c_str(), &spwd, buffer.data(), buflen, &spwdPtr);
    // On success, getspnam_r() returns zero, and sets *spwdPtr to spwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *spwdPtr
    if ((status == 0) && (&spwd == spwdPtr))
    {
        // Determine password validity per "chage" docs, where:
        //   spwd.sp_lstchg == 0 means password is expired, and
        //   spwd.sp_max == -1 means the password does not expire.
        constexpr long secondsPerDay = 60 * 60 * 24;
        long today = static_cast<long>(time(NULL)) / secondsPerDay;
        if ((spwd.sp_lstchg == 0) ||
            ((spwd.sp_max != -1) && ((spwd.sp_max + spwd.sp_lstchg) < today)))
        {
            return true;
        }
    }
    else
    {
        // User entry is missing in /etc/shadow, indicating no SHA password.
        // Treat this as new user without password entry in /etc/shadow
        // TODO: Add property to indicate user password was not set yet
        // https://github.com/openbmc/phosphor-user-manager/issues/8
        return false;
    }

    return false;
}

UserSSHLists UserMgr::getUserAndSshGrpList()
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    std::vector<std::string> userList;
    std::vector<std::string> sshUsersList;
    struct passwd pw, *pwp = nullptr;
    std::array<char, 1024> buffer{};

    phosphor::user::File passwd(passwdFileName, "r");
    if ((passwd)() == NULL)
    {
        log<level::ERR>("Error opening the passwd file");
        elog<InternalFailure>();
    }

    while (true)
    {
        auto r = fgetpwent_r((passwd)(), &pw, buffer.data(), buffer.max_size(),
                             &pwp);
        if ((r != 0) || (pwp == NULL))
        {
            // Any error, break the loop.
            break;
        }
#ifdef ENABLE_ROOT_USER_MGMT
        // Add all users whose UID >= 1000 and < 65534
        // and special UID 0.
        if ((pwp->pw_uid == 0) ||
            ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534)))
#else
        // Add all users whose UID >=1000 and < 65534
        if ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534))
#endif
        {
            std::string userName(pwp->pw_name);
            userList.emplace_back(userName);

            // ssh doesn't have separate group. Check login shell entry to
            // get all users list which are member of ssh group.
            std::string loginShell(pwp->pw_shell);
            if (loginShell == "/bin/sh")
            {
                sshUsersList.emplace_back(userName);
            }
        }
    }
    endpwent();
    return std::make_pair(std::move(userList), std::move(sshUsersList));
}

size_t UserMgr::getIpmiUsersCount()
{
    std::vector<std::string> userList = getUsersInGroup("ipmi");
    return userList.size();
}

size_t UserMgr::getNonIpmiUsersCount()
{
    std::vector<std::string> ipmiUsers = getUsersInGroup("ipmi");
    return usersList.size() - ipmiUsers.size();
}

bool UserMgr::isUserEnabled(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::array<char, 4096> buffer{};
    struct spwd spwd;
    struct spwd* resultPtr = nullptr;
    int status = getspnam_r(userName.c_str(), &spwd, buffer.data(),
                            buffer.max_size(), &resultPtr);
    if (!status && (&spwd == resultPtr))
    {
        if (resultPtr->sp_expire >= 0)
        {
            return false; // user locked out
        }
        return true;
    }
    return false; // assume user is disabled for any error.
}

std::vector<std::string> UserMgr::getUsersInGroup(const std::string& groupName)
{
    std::vector<std::string> usersInGroup;
    // Should be more than enough to get the pwd structure.
    std::array<char, 4096> buffer{};
    struct group grp;
    struct group* resultPtr = nullptr;

    int status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.max_size(), &resultPtr);

    if (!status && (&grp == resultPtr))
    {
        for (; *(grp.gr_mem) != NULL; ++(grp.gr_mem))
        {
            usersInGroup.emplace_back(*(grp.gr_mem));
        }
    }
    else
    {
        log<level::ERR>("Group not found",
                        entry("GROUP=%s", groupName.c_str()));
        // Don't throw error, just return empty userList - fallback
    }
    return usersInGroup;
}

DbusUserObj UserMgr::getPrivilegeMapperObject(void)
{
    DbusUserObj objects;
    try
    {
        std::string basePath = "/xyz/openbmc_project/user/ldap/openldap";
        std::string interface = "xyz.openbmc_project.User.Ldap.Config";

        auto ldapMgmtService =
            getServiceName(std::move(basePath), std::move(interface));
        auto method = bus.new_method_call(
            ldapMgmtService.c_str(), ldapMgrObjBasePath,
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Unable to get the User Service",
                        entry("WHAT=%s", e.what()));
        throw;
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>(
            "Failed to excute method", entry("METHOD=%s", "GetManagedObjects"),
            entry("PATH=%s", ldapMgrObjBasePath), entry("WHAT=%s", e.what()));
        throw;
    }
    return objects;
}

std::string UserMgr::getServiceName(std::string&& path, std::string&& intf)
{
    auto mapperCall = bus.new_method_call(objMapperService, objMapperPath,
                                          objMapperInterface, "GetObject");

    mapperCall.append(std::move(path));
    mapperCall.append(std::vector<std::string>({std::move(intf)}));

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        log<level::ERR>("Invalid response from mapper");
        elog<InternalFailure>();
    }

    return mapperResponse.begin()->first;
}

gid_t UserMgr::getPrimaryGroup(const std::string& userName) const
{
    static auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct passwd pwd;
    struct passwd* pwdPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getpwnam_r(userName.c_str(), &pwd, buffer.data(),
                             buffer.size(), &pwdPtr);
    // On success, getpwnam_r() returns zero, and set *pwdPtr to pwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *pwdPtr
    if (!status && (&pwd == pwdPtr))
    {
        return pwd.pw_gid;
    }

    log<level::ERR>("User noes not exist",
                    entry("USER_NAME=%s", userName.c_str()));
    elog<UserNameDoesNotExist>();
}

bool UserMgr::isGroupMember(const std::string& userName, gid_t primaryGid,
                            const std::string& groupName) const
{
    static auto buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct group grp;
    struct group* grpPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                             buffer.size(), &grpPtr);

    // Groups with a lot of members may require a buffer of bigger size than
    // suggested by _SC_GETGR_R_SIZE_MAX.
    // 32K should be enough for about 2K members.
    constexpr auto maxBufferLength = 32 * 1024;
    while (status == ERANGE && buflen < maxBufferLength)
    {
        buflen *= 2;
        buffer.resize(buflen);

        log<level::DEBUG>("Increase buffer for getgrnam_r()",
                          entry("BUFFER_LENGTH=%zu", buflen));

        status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.size(), &grpPtr);
    }

    // On success, getgrnam_r() returns zero, and set *grpPtr to grp.
    // If no matching group record was found, these functions return 0
    // and store NULL in *grpPtr
    if (!status && (&grp == grpPtr))
    {
        if (primaryGid == grp.gr_gid)
        {
            return true;
        }

        for (auto i = 0; grp.gr_mem && grp.gr_mem[i]; ++i)
        {
            if (userName == grp.gr_mem[i])
            {
                return true;
            }
        }
    }
    else if (status == ERANGE)
    {
        log<level::ERR>("Group info requires too much memory",
                        entry("GROUP_NAME=%s", groupName.c_str()));
    }
    else
    {
        log<level::ERR>("Group does not exist",
                        entry("GROUP_NAME=%s", groupName.c_str()));
    }

    return false;
}

UserInfoMap UserMgr::getUserInfo(std::string userName)
{
    UserInfoMap userInfo;
    // Check whether the given user is local user or not.
    if (isUserExist(userName))
    {
        const auto& user = usersList[userName];
        userInfo.emplace("UserPrivilege", user.get()->userPrivilege());
        userInfo.emplace("UserGroups", user.get()->userGroups());
        userInfo.emplace("UserEnabled", user.get()->userEnabled());
        userInfo.emplace("UserLockedForFailedAttempt",
                         user.get()->userLockedForFailedAttempt());
        userInfo.emplace("UserPasswordExpired",
                         user.get()->userPasswordExpired());
        userInfo.emplace("RemoteUser", false);
    }
    else
    {
        auto primaryGid = getPrimaryGroup(userName);

        DbusUserObj objects = getPrivilegeMapperObject();

        std::string ldapConfigPath;
        std::string userPrivilege;

        try
        {
            for (const auto& [path, interfaces] : objects)
            {
                auto it = interfaces.find("xyz.openbmc_project.Object.Enable");
                if (it != interfaces.end())
                {
                    auto propIt = it->second.find("Enabled");
                    if (propIt != it->second.end() &&
                        std::get<bool>(propIt->second))
                    {
                        ldapConfigPath = path.str + '/';
                        break;
                    }
                }
            }

            if (ldapConfigPath.empty())
            {
                return userInfo;
            }

            for (const auto& [path, interfaces] : objects)
            {
                if (!path.str.starts_with(ldapConfigPath))
                {
                    continue;
                }

                auto it = interfaces.find(
                    "xyz.openbmc_project.User.PrivilegeMapperEntry");
                if (it != interfaces.end())
                {
                    std::string privilege;
                    std::string groupName;

                    for (const auto& [propName, propValue] : it->second)
                    {
                        if (propName == "GroupName")
                        {
                            groupName = std::get<std::string>(propValue);
                        }
                        else if (propName == "Privilege")
                        {
                            privilege = std::get<std::string>(propValue);
                        }
                    }

                    if (!groupName.empty() && !privilege.empty() &&
                        isGroupMember(userName, primaryGid, groupName))
                    {
                        userPrivilege = privilege;
                        break;
                    }
                }
                if (!userPrivilege.empty())
                {
                    break;
                }
            }

            if (userPrivilege.empty())
            {
                log<level::ERR>("LDAP group privilege mapping does not exist");
            }
            userInfo.emplace("UserPrivilege", userPrivilege);
        }
        catch (const std::bad_variant_access& e)
        {
            log<level::ERR>("Error while accessing variant",
                            entry("WHAT=%s", e.what()));
            elog<InternalFailure>();
        }
        userInfo.emplace("RemoteUser", true);
    }

    return userInfo;
}

void UserMgr::initializeAccountPolicy()
{
    std::string valueStr;
    auto value = minPasswdLength;
    unsigned long tmp = 0;

    if (getPamModuleArgValue(pamPWQuality, minPasswdLenProp, valueStr) !=
        success)
    {
        AccountPolicyIface::minPasswordLength(minPasswdLength);
    }
    else
    {
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception for MinPasswordLength",
                            entry("WHAT=%s", e.what()));
            throw;
        }
        AccountPolicyIface::minPasswordLength(value);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamPWHistory, remOldPasswdCount, valueStr) !=
        success)
    {
        AccountPolicyIface::rememberOldPasswordTimes(0);
    }
    else
    {
        value = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception for RememberOldPasswordTimes",
                            entry("WHAT=%s", e.what()));
            throw;
        }
        AccountPolicyIface::rememberOldPasswordTimes(value);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamFaillock, maxFailedAttempt, valueStr) !=
        success)
    {
        AccountPolicyIface::maxLoginAttemptBeforeLockout(0);
    }
    else
    {
        uint16_t value16 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value16)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value16 = static_cast<decltype(value16)>(tmp);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception for MaxLoginAttemptBeforeLockout",
                            entry("WHAT=%s", e.what()));
            throw;
        }
        AccountPolicyIface::maxLoginAttemptBeforeLockout(value16);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamFaillock, unlockTimeout, valueStr) != success)
    {
        AccountPolicyIface::accountUnlockTimeout(0);
    }
    else
    {
        uint32_t value32 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value32)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value32 = static_cast<decltype(value32)>(tmp);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception for AccountUnlockTimeout",
                            entry("WHAT=%s", e.what()));
            throw;
        }
        AccountPolicyIface::accountUnlockTimeout(value32);
    }
}

void UserMgr::initUserObjects(void)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::vector<std::string> userNameList;
    std::vector<std::string> sshGrpUsersList;
    UserSSHLists userSSHLists = getUserAndSshGrpList();
    userNameList = std::move(userSSHLists.first);
    sshGrpUsersList = std::move(userSSHLists.second);

    if (!userNameList.empty())
    {
        std::map<std::string, std::vector<std::string>> groupLists;
        for (auto& grp : groupsMgr)
        {
            if (grp == grpSsh)
            {
                groupLists.emplace(grp, sshGrpUsersList);
            }
            else
            {
                std::vector<std::string> grpUsersList = getUsersInGroup(grp);
                groupLists.emplace(grp, grpUsersList);
            }
        }
        for (auto& grp : privMgr)
        {
            std::vector<std::string> grpUsersList = getUsersInGroup(grp);
            groupLists.emplace(grp, grpUsersList);
        }

        for (auto& user : userNameList)
        {
            std::vector<std::string> userGroups;
            std::string userPriv;
            for (const auto& grp : groupLists)
            {
                std::vector<std::string> tempGrp = grp.second;
                if (std::find(tempGrp.begin(), tempGrp.end(), user) !=
                    tempGrp.end())
                {
                    if (std::find(privMgr.begin(), privMgr.end(), grp.first) !=
                        privMgr.end())
                    {
                        userPriv = grp.first;
                    }
                    else
                    {
                        userGroups.emplace_back(grp.first);
                    }
                }
            }
            // Add user objects to the Users path.
            sdbusplus::message::object_path tempObjPath(usersObjPath);
            tempObjPath /= user;
            std::string objPath(tempObjPath);
            std::sort(userGroups.begin(), userGroups.end());
            usersList.emplace(user, std::make_unique<phosphor::user::Users>(
                                        bus, objPath.c_str(), userGroups,
                                        userPriv, isUserEnabled(user), *this));
        }
    }
}

UserMgr::UserMgr(sdbusplus::bus_t& bus, const char* path) :
    Ifaces(bus, path, Ifaces::action::defer_emit), bus(bus), path(path),
    pamPasswdConfigFile(defaultPamPasswdConfigFile),
    pamAuthConfigFile(faillockConfigFile)
{
    UserMgrIface::allPrivileges(privMgr);
    std::sort(groupsMgr.begin(), groupsMgr.end());
    UserMgrIface::allGroups(groupsMgr);
    initializeAccountPolicy();
    initUserObjects();

    // emit the signal
    this->emit_object_added();
}

void UserMgr::executeUserAdd(const char* userName, const char* groups,
                             bool sshRequested, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/useradd", userName, "-G", groups, "-m", "-N", "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"), "-e",
               (enabled ? "" : "1970-01-01"));
}

void UserMgr::executeUserDelete(const char* userName)
{
    executeCmd("/usr/sbin/userdel", userName, "-r");
}

void UserMgr::executeUserClearFailRecords(const char* userName)
{
    executeCmd("/usr/sbin/faillock", "--user", userName, "--reset");
}

void UserMgr::executeUserRename(const char* userName, const char* newUserName)
{
    std::string newHomeDir = "/home/";
    newHomeDir += newUserName;
    executeCmd("/usr/sbin/usermod", "-l", newUserName, userName, "-d",
               newHomeDir.c_str(), "-m");
}

void UserMgr::executeUserModify(const char* userName, const char* newGroups,
                                bool sshRequested)
{
    executeCmd("/usr/sbin/usermod", userName, "-G", newGroups, "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"));
}

void UserMgr::executeUserModifyUserEnable(const char* userName, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/usermod", userName, "-e",
               (enabled ? "" : "1970-01-01"));
}

std::vector<std::string> UserMgr::getFailedAttempt(const char* userName)
{
    // Emulate the behavior of pam_faillock.so authsucc: get the number of
    // failed attempts and compare with the deny= value
    // See https://github.com/linux-pam/linux-pam/issues/327
    return executeCmd("/usr/sbin/faillock", "--user", userName);
}

void UserMgr::createGroup(std::string /*groupName*/)
{
    log<level::ERR>("Not implemented yet");
    elog<InternalFailure>();
}

void UserMgr::deleteGroup(std::string /*groupName*/)
{
    log<level::ERR>("Not implemented yet");
    elog<InternalFailure>();
}

} // namespace user
} // namespace phosphor
