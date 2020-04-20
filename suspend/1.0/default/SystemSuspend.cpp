/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "SystemSuspend.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <google/protobuf/text_format.h>
#include <hidl/Status.h>
#include <hwbinder/IPCThreadState.h>

#include <linux/uinput.h>
#include <dirent.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <ctime>
#include <string>
#include <thread>

using ::android::base::GetBoolProperty;
using ::android::base::GetProperty;
using ::android::base::ReadFdToString;
using ::android::base::WriteStringToFd;
using ::android::base::StringPrintf;
using ::android::hardware::Void;
using ::std::string;

namespace android {
namespace system {
namespace suspend {
namespace V1_0 {

static const char kSleepState[] = "mem";
// TODO(b/128923994): we only need /sys/power/wake_[un]lock to export debugging info via
// /sys/kernel/debug/wakeup_sources.
static constexpr char kSysPowerWakeLock[] = "/sys/power/wake_lock";
static constexpr char kSysPowerWakeUnlock[] = "/sys/power/wake_unlock";

class PowerbtndThread {
   public:
    PowerbtndThread();
    void sendKeyPower(bool longpress);
    void sendKeyWakeup();

   private:
    void emitKey(int key_code, int val);
    void run();
    unique_fd mUinputFd;
};

PowerbtndThread::PowerbtndThread()
    : mUinputFd(open("/dev/uinput", O_WRONLY | O_NDELAY))
{
    if (mUinputFd < 0) {
        LOG(ERROR) << "could not open uinput device: " << strerror(errno);
        return;
    }

    struct uinput_user_dev ud;
    memset(&ud, 0, sizeof(ud));
    strcpy(ud.name, "Android Power Button");
    write(mUinputFd, &ud, sizeof(ud));
    ioctl(mUinputFd, UI_SET_EVBIT, EV_KEY);
    ioctl(mUinputFd, UI_SET_KEYBIT, KEY_POWER);
    ioctl(mUinputFd, UI_SET_KEYBIT, KEY_WAKEUP);
    ioctl(mUinputFd, UI_DEV_CREATE, 0);

    std::thread([this] { run(); }).detach();
    LOG(INFO) << "automatic system suspend enabled";
}

void PowerbtndThread::sendKeyPower(bool longpress)
{
    emitKey(KEY_POWER, 1);
    if (longpress) sleep(2);
    emitKey(KEY_POWER, 0);
}

void PowerbtndThread::sendKeyWakeup()
{
    emitKey(KEY_WAKEUP, 1);
    emitKey(KEY_WAKEUP, 0);
}

void PowerbtndThread::emitKey(int key_code, int val)
{
    struct input_event iev;
    iev.type = EV_KEY;
    iev.code = key_code;
    iev.value = val;
    iev.time.tv_sec = 0;
    iev.time.tv_usec = 0;
    write(mUinputFd, &iev, sizeof(iev));
    iev.type = EV_SYN;
    iev.code = SYN_REPORT;
    iev.value = 0;
    write(mUinputFd, &iev, sizeof(iev));
    LOG(INFO) << StringPrintf("send key %d (%d) on fd %d", key_code, val, mUinputFd.get());
}

void PowerbtndThread::run()
{
    int cnt = 0, timeout = -1, pollres;
    bool longpress = true;
    bool doubleclick = GetBoolProperty("poweroff.doubleclick", false);
    struct pollfd pfds[3];
    const char *dirname = "/dev/input";

    if (DIR *dir = opendir(dirname)) {
        struct dirent *de;
        while ((cnt < 3) && (de = readdir(dir))) {
            int fd;
            char name[PATH_MAX];
            if (de->d_name[0] != 'e') /* eventX */
                continue;
            snprintf(name, PATH_MAX, "%s/%s", dirname, de->d_name);
            fd = open(name, O_RDWR | O_NONBLOCK);
            if (fd < 0) {
                LOG(ERROR) << StringPrintf("could not open %s, %s", name, strerror(errno));
                continue;
            }
            name[sizeof(name) - 1] = '\0';
            if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), &name) < 1) {
                LOG(ERROR) << StringPrintf("could not get device name for %s, %s", name, strerror(errno));
                name[0] = '\0';
            }
            // TODO: parse /etc/excluded-input-devices.xml
            if (strcmp(name, "Power Button")) {
                close(fd);
                continue;
            }

            LOG(INFO) << StringPrintf("open %s(%s) ok fd=%d", de->d_name, name, fd);
            pfds[cnt].events = POLLIN;
            pfds[cnt++].fd = fd;
        }
        closedir(dir);
    }

    while (cnt > 0) {
        if ((pollres = poll(pfds, cnt, timeout)) < 0) {
            LOG(ERROR) << "poll error: " << strerror(errno);
            break;
        }
        LOG(VERBOSE) << "pollres=" << pollres << " timeout=" << timeout;
        if (pollres == 0) {
            LOG(INFO) << "timeout, send one power key";
            sendKeyPower(0);
            timeout = -1;
            longpress = true;
            continue;
        }
        for (int i = 0; i < cnt; ++i) {
            if (pfds[i].revents & POLLIN) {
                struct input_event iev;
                size_t res = read(pfds[i].fd, &iev, sizeof(iev));
                if (res < sizeof(iev)) {
                    LOG(WARNING) << StringPrintf("insufficient input data(%zd)? fd=%d", res, pfds[i].fd);
                    continue;
                }
                LOG(DEBUG) << StringPrintf("type=%d code=%d value=%d from fd=%d", iev.type, iev.code, iev.value, pfds[i].fd);
                if (iev.type == EV_KEY && iev.code == KEY_POWER && !iev.value) {
                    if (!doubleclick || timeout > 0) {
                        sendKeyPower(longpress);
                        timeout = -1;
                    } else {
                        timeout = 1000; // one second
                    }
                } else if (iev.type == EV_SYN && iev.code == SYN_REPORT && iev.value) {
                    LOG(INFO) << "got a resuming event";
                    longpress = false;
                    timeout = 1000; // one second
                }
            }
        }
    }
}

// This function assumes that data in fd is small enough that it can be read in one go.
// We use this function instead of the ones available in libbase because it doesn't block
// indefinitely when reading from socket streams which are used for testing.
string readFd(int fd) {
    char buf[BUFSIZ];
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)));
    if (n < 0) return "";
    return string{buf, static_cast<size_t>(n)};
}

static inline int getCallingPid() {
    return ::android::hardware::IPCThreadState::self()->getCallingPid();
}

static inline WakeLockIdType getWakeLockId(int pid, const string& name) {
    // Doesn't guarantee unique ids, but for debuging purposes this is adequate.
    return std::to_string(pid) + "/" + name;
}

TimestampType getEpochTimeNow() {
    auto timeSinceEpoch = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(timeSinceEpoch).count();
}

WakeLock::WakeLock(SystemSuspend* systemSuspend, const WakeLockIdType& id, const string& name)
    : mReleased(), mSystemSuspend(systemSuspend), mId(id), mName(name) {
    mSystemSuspend->incSuspendCounter(mName);
}

WakeLock::~WakeLock() {
    releaseOnce();
}

Return<void> WakeLock::release() {
    releaseOnce();
    return Void();
}

void WakeLock::releaseOnce() {
    std::call_once(mReleased, [this]() {
        mSystemSuspend->decSuspendCounter(mName);
        mSystemSuspend->deleteWakeLockStatsEntry(mId);
    });
}

SystemSuspend::SystemSuspend(unique_fd wakeupCountFd, unique_fd stateFd, size_t maxStatsEntries,
                             std::chrono::milliseconds baseSleepTime,
                             const sp<SuspendControlService>& controlService,
                             bool useSuspendCounter)
    : mSuspendCounter(0),
      mWakeupCountFd(std::move(wakeupCountFd)),
      mStateFd(std::move(stateFd)),
      mPwrbtnd(new PowerbtndThread()),
      mMaxStatsEntries(maxStatsEntries),
      mBaseSleepTime(baseSleepTime),
      mSleepTime(baseSleepTime),
      mControlService(controlService),
      mUseSuspendCounter(useSuspendCounter),
      mWakeLockFd(-1),
      mWakeUnlockFd(-1) {
    mControlService->setSuspendService(this);

    if (!mUseSuspendCounter) {
        mWakeLockFd.reset(TEMP_FAILURE_RETRY(open(kSysPowerWakeLock, O_CLOEXEC | O_RDWR)));
        if (mWakeLockFd < 0) {
            PLOG(ERROR) << "error opening " << kSysPowerWakeLock;
        }
        mWakeUnlockFd.reset(TEMP_FAILURE_RETRY(open(kSysPowerWakeUnlock, O_CLOEXEC | O_RDWR)));
        if (mWakeUnlockFd < 0) {
            PLOG(ERROR) << "error opening " << kSysPowerWakeUnlock;
        }
    }
}

bool SystemSuspend::enableAutosuspend() {
    static bool initialized = false;
    if (initialized) {
        LOG(ERROR) << "Autosuspend already started.";
        return false;
    }

    initAutosuspend();
    initialized = true;
    return true;
}

bool SystemSuspend::forceSuspend() {
    //  We are forcing the system to suspend. This particular call ignores all
    //  existing wakelocks (full or partial). It does not cancel the wakelocks
    //  or reset mSuspendCounter, it just ignores them.  When the system
    //  returns from suspend, the wakelocks and SuspendCounter will not have
    //  changed.
    auto counterLock = std::unique_lock(mCounterLock);
    bool success = WriteStringToFd(getSleepState(), mStateFd);
    counterLock.unlock();

    if (!success) {
        PLOG(VERBOSE) << "error writing to /sys/power/state for forceSuspend";
    }
    return success;
}

Return<sp<IWakeLock>> SystemSuspend::acquireWakeLock(WakeLockType /* type */,
                                                     const hidl_string& name) {
    auto pid = getCallingPid();
    auto wlId = getWakeLockId(pid, name);
    IWakeLock* wl = new WakeLock{this, wlId, name};
    {
        auto l = std::lock_guard(mStatsLock);

        auto& wlStatsEntry = (*mStats.mutable_wl_stats())[wlId];
        auto lastUpdated = wlStatsEntry.last_updated();
        auto timeNow = getEpochTimeNow();
        mLruWakeLockId.erase(lastUpdated);
        mLruWakeLockId[timeNow] = wlId;

        wlStatsEntry.set_name(name);
        wlStatsEntry.set_pid(pid);
        wlStatsEntry.set_active(true);
        wlStatsEntry.set_last_updated(timeNow);

        if (mStats.wl_stats().size() > mMaxStatsEntries) {
            auto lruWakeLockId = mLruWakeLockId.begin()->second;
            mLruWakeLockId.erase(mLruWakeLockId.begin());
            mStats.mutable_wl_stats()->erase(lruWakeLockId);
        }
    }
    return wl;
}

Return<void> SystemSuspend::debug(const hidl_handle& handle,
                                  const hidl_vec<hidl_string>& /* options */) {
    if (handle == nullptr || handle->numFds < 1 || handle->data[0] < 0) {
        LOG(ERROR) << "no valid fd";
        return Void();
    }
    int fd = handle->data[0];
    string debugStr;
    {
        auto l = std::lock_guard(mStatsLock);
        google::protobuf::TextFormat::PrintToString(mStats, &debugStr);
    }
    WriteStringToFd(debugStr, fd);
    fsync(fd);
    return Void();
}

void SystemSuspend::incSuspendCounter(const string& name) {
    auto l = std::lock_guard(mCounterLock);
    if (mUseSuspendCounter) {
        mSuspendCounter++;
    } else {
        if (!WriteStringToFd(name, mWakeLockFd)) {
            PLOG(ERROR) << "error writing " << name << " to " << kSysPowerWakeLock;
        }
    }
}

void SystemSuspend::decSuspendCounter(const string& name) {
    auto l = std::lock_guard(mCounterLock);
    if (mUseSuspendCounter) {
        if (--mSuspendCounter == 0) {
            mCounterCondVar.notify_one();
        }
    } else {
        if (!WriteStringToFd(name, mWakeUnlockFd)) {
            PLOG(ERROR) << "error writing " << name << " to " << kSysPowerWakeUnlock;
        }
    }
}

void SystemSuspend::deleteWakeLockStatsEntry(WakeLockIdType id) {
    auto l = std::lock_guard(mStatsLock);
    auto* wlStats = mStats.mutable_wl_stats();
    if (wlStats->find(id) != wlStats->end()) {
        auto& wlStatsEntry = (*wlStats)[id];
        auto timeNow = getEpochTimeNow();
        auto lastUpdated = wlStatsEntry.last_updated();
        wlStatsEntry.set_active(false);
        wlStatsEntry.set_last_updated(timeNow);
        mLruWakeLockId.erase(lastUpdated);
        mLruWakeLockId[timeNow] = id;
    }
}

void SystemSuspend::initAutosuspend() {
    std::thread autosuspendThread([this] {
        while (true) {
            std::this_thread::sleep_for(mSleepTime);
            lseek(mWakeupCountFd, 0, SEEK_SET);
            const string wakeupCount = readFd(mWakeupCountFd);
            if (wakeupCount.empty()) {
                PLOG(ERROR) << "error reading from /sys/power/wakeup_count";
                continue;
            }

            auto counterLock = std::unique_lock(mCounterLock);
            mCounterCondVar.wait(counterLock, [this] { return mSuspendCounter == 0; });
            // The mutex is locked and *MUST* remain locked until we write to /sys/power/state.
            // Otherwise, a WakeLock might be acquired after we check mSuspendCounter and before we
            // write to /sys/power/state.

            if (!WriteStringToFd(wakeupCount, mWakeupCountFd)) {
                PLOG(VERBOSE) << "error writing from /sys/power/wakeup_count";
                continue;
            }
            bool success = WriteStringToFd(getSleepState(), mStateFd);
            counterLock.unlock();

            if (!success) {
                PLOG(VERBOSE) << "error writing to /sys/power/state";
            } else {
                mPwrbtnd->sendKeyWakeup();
            }

            mControlService->notifyWakeup(success);

            updateSleepTime(success);
        }
    });
    autosuspendThread.detach();
    LOG(INFO) << "automatic system suspend enabled";
}

const string &SystemSuspend::getSleepState() {
    if (mSleepState.empty()) {
        mSleepState = GetProperty("sleep.state", "");
        if (!mSleepState.empty()) {
            LOG(INFO) << "autosuspend using sleep.state property " << mSleepState;
        } else {
            string buf = readFd(mStateFd);
            if (buf.find(kSleepState) != std::string::npos) {
                mSleepState = kSleepState;
                LOG(INFO) << "autosuspend using default sleep_state " << mSleepState;
            } else {
                mSleepState = "freeze";
                LOG(WARNING) << "autosuspend using fallback state " << mSleepState;
            }
        }
    }
    return mSleepState;
}

void SystemSuspend::updateSleepTime(bool success) {
    static constexpr std::chrono::milliseconds kMaxSleepTime = 1min;
    if (success) {
        mSleepTime = mBaseSleepTime;
        return;
    }
    // Double sleep time after each failure up to one minute.
    mSleepTime = std::min(mSleepTime * 2, kMaxSleepTime);
}

}  // namespace V1_0
}  // namespace suspend
}  // namespace system
}  // namespace android
