#pragma once
#include "pin.H"
#include "PinLocker.h"
#include <string>
#include <set>


struct LoadedImage
{
    std::string name_;
    ADDRINT low_;
    ADDRINT high_;
    ADDRINT desired_base_;

    LoadedImage(std::string n = "", ADDRINT low = 0, ADDRINT high = 0, ADDRINT desired_base = 0)
        : name_(std::move(n))
          , low_(low)
          , high_(high)
          , desired_base_(desired_base) {}

    // Overloaded method to implement searches over the loaded images list
    // and also allow this class to be used on a set like STL container.
    bool operator<(const LoadedImage& rhs) const {
        return low_ < rhs.low_;
    }

    ADDRINT getDesiredBase() const {
        return desired_base_;
    }

    void setDesiredBase(ADDRINT base) {
        desired_base_ = base;
    }
};

class ImageManager
{
private:
    // Set of module names that are allowed to be traced.
    std::set<LoadedImage> images;
    PinRwMutex images_lock;

    // Here we store the names of the images inside our white list.
    std::set<std::string> whitelist;

    // Store the last recently matched image so we can use it as a cache.
    ADDRINT m_cached_low;
    ADDRINT m_cached_high;

public:
    ImageManager() : m_cached_low(0), m_cached_high(0) {}

    VOID addWhiteListedImage(const std::string& image_name) {
        whitelist.insert(image_name);
    }

    BOOL isWhiteListed(const std::string& image_name) {
        return whitelist.find(image_name) != whitelist.end();
    }

    /**
     *  Checks if the given address falls inside one of the white-listed images we are
     *  tracing.
     * @param addr
     * @return true if the address is interesting, false otherwise.
     */
    BOOL isInterestingAddress(ADDRINT addr) {
        auto lock = images_lock.acquire_read();

        // If there is no white-listed image, everything is white-listed.
        if (images.empty() || (addr >= m_cached_low && addr < m_cached_high)) {
            return true;
        }

        auto i = images.upper_bound(LoadedImage("", addr));
        if (i == images.begin()) {
            return false;
        }
        --i;

        // If the instruction address does not fall inside a valid white listed image, bail out.
        if (!(i != images.end() && i->low_ <= addr && addr < i->high_)) {
            return false;
        }

        // Save the matched image.
        m_cached_low = i->low_;
        m_cached_high = i->high_;

        return true;
    }


    VOID addImage(std::string image_name, ADDRINT lo_addr, ADDRINT hi_addr) {
        addImage(image_name, lo_addr, hi_addr, 0);
    }

    VOID addImage(std::string image_name, ADDRINT lo_addr, ADDRINT hi_addr, ADDRINT desired_base) {
        auto lock = images_lock.acquire_write();
        images.insert(LoadedImage(image_name, lo_addr, hi_addr, desired_base));
    }

    VOID removeImage(ADDRINT low) {
        auto lock = images_lock.acquire_write();
        std::set<LoadedImage>::iterator i = images.find(LoadedImage("", low));
        if (i != images.end()) {
            LoadedImage li = *i;
            images.erase(i);
        }
    }

    /*
     *
     * Set the desired base for an image by name (after loading)
     */
    VOID setDesiredBase(const std::string& image_name, ADDRINT desired_base) {
        auto lock = images_lock.acquire_write();
        for (std::set<LoadedImage>::iterator it = images.begin(); it != images.end(); ++it) {
            if (it->name_ == image_name) {
                LoadedImage updated = *it;
                images.erase(it);
                updated.setDesiredBase(desired_base);
                images.insert(updated);
                break;
            }
        }
    }
};
