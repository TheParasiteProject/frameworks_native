/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_SF_FRAMEBUFFER_SURFACE_H
#define ANDROID_SF_FRAMEBUFFER_SURFACE_H

#include <stdint.h>
#include <sys/types.h>

#include <com_android_graphics_libgui_flags.h>
#include <compositionengine/DisplaySurface.h>
#include <gui/BufferQueue.h>
#include <gui/ConsumerBase.h>
#include <ui/DisplayId.h>
#include <ui/Size.h>

#include <ui/DisplayIdentification.h>

// ---------------------------------------------------------------------------
namespace android {
// ---------------------------------------------------------------------------

class Rect;
class String8;
class HWComposer;

// ---------------------------------------------------------------------------

class FramebufferSurface : public ConsumerBase, public compositionengine::DisplaySurface {
public:
#if COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
    FramebufferSurface(HWComposer& hwc, PhysicalDisplayId displayId,
                       const sp<IGraphicBufferProducer>& producer,
                       const sp<IGraphicBufferConsumer>& consumer, const ui::Size& size,
                       const ui::Size& maxSize);
#else
    FramebufferSurface(HWComposer& hwc, PhysicalDisplayId displayId,
                       const sp<IGraphicBufferConsumer>& consumer, const ui::Size& size,
                       const ui::Size& maxSize);
#endif // COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)

    virtual status_t beginFrame(bool mustRecompose);
    virtual status_t prepareFrame(CompositionType compositionType);
    virtual status_t advanceFrame(float hdrSdrRatio);
    virtual void onFrameCommitted();
    virtual void dumpAsString(String8& result) const;

    virtual void resizeBuffers(const ui::Size&) override;

    virtual const sp<Fence>& getClientTargetAcquireFence() const override;

private:
    friend class FramebufferSurfaceTest;

    // Limits the width and height by the maximum width specified.
    ui::Size limitSize(const ui::Size&);

    // Used for testing purposes.
    static ui::Size limitSizeInternal(const ui::Size&, const ui::Size& maxSize);

    virtual ~FramebufferSurface() { }; // this class cannot be overloaded

    virtual void freeBufferLocked(int slotIndex);

    virtual void dumpLocked(String8& result, const char* prefix) const;

    const PhysicalDisplayId mDisplayId;

    // Framebuffer size has a dimension limitation in pixels based on the graphics capabilities of
    // the device.
    const ui::Size mMaxSize;

    // mCurrentBufferIndex is the slot index of the current buffer or
    // INVALID_BUFFER_SLOT to indicate that either there is no current buffer
    // or the buffer is not associated with a slot.
    int mCurrentBufferSlot;

    // mDataSpace is the dataspace of the current composition buffer for
    // this FramebufferSurface. It will be 0 when HWC is doing the
    // compositing. Otherwise it will display the dataspace of the buffer
    // use for compositing which can change as wide-color content is
    // on/off.
    ui::Dataspace mDataspace;

    // mCurrentBuffer is the current buffer or nullptr to indicate that there is
    // no current buffer.
    sp<GraphicBuffer> mCurrentBuffer;

    // mCurrentFence is the current buffer's acquire fence
    sp<Fence> mCurrentFence;

    // Hardware composer, owned by SurfaceFlinger.
    HWComposer& mHwc;

    // Buffers that HWC has seen before, indexed by slot number.
    // NOTE: The BufferQueue slot number is the same as the HWC slot number.
    uint64_t mHwcBufferIds[BufferQueue::NUM_BUFFER_SLOTS];

    // Previous buffer to release after getting an updated retire fence
    bool mHasPendingRelease;
    int mPreviousBufferSlot;
    sp<GraphicBuffer> mPreviousBuffer;
};

// ---------------------------------------------------------------------------
}; // namespace android
// ---------------------------------------------------------------------------

#endif // ANDROID_SF_FRAMEBUFFER_SURFACE_H

