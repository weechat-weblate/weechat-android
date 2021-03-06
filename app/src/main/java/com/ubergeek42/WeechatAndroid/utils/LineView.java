// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package com.ubergeek42.WeechatAndroid.utils;

import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.Spannable;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.bumptech.glide.Glide;
import com.bumptech.glide.request.target.CustomTarget;
import com.bumptech.glide.request.transition.Transition;
import com.ubergeek42.WeechatAndroid.Weechat;
import com.ubergeek42.WeechatAndroid.media.Cache;
import com.ubergeek42.WeechatAndroid.media.Config;
import com.ubergeek42.WeechatAndroid.media.Engine;
import com.ubergeek42.WeechatAndroid.media.Strategy;
import com.ubergeek42.WeechatAndroid.relay.Line;
import com.ubergeek42.WeechatAndroid.service.P;
import com.ubergeek42.cats.Kitty;
import com.ubergeek42.cats.Root;

import java.util.List;

import static com.ubergeek42.WeechatAndroid.media.Config.ANIMATION_DURATION;
import static com.ubergeek42.WeechatAndroid.media.Config.THUMBNAIL_HORIZONTAL_MARGIN;
import static com.ubergeek42.WeechatAndroid.media.Config.THUMBNAIL_VERTICAL_MARGIN;
import static com.ubergeek42.WeechatAndroid.media.Config.thumbnailMaxHeight;
import static com.ubergeek42.WeechatAndroid.media.Config.thumbnailMinHeight;
import static com.ubergeek42.WeechatAndroid.media.Config.thumbnailWidth;
import static com.ubergeek42.WeechatAndroid.utils.Assert.assertThat;

public class LineView extends View {
    final private @Root Kitty kitty = Kitty.make();

    private enum State {
        TEXT_ONLY,                      // wide layout, no image
        WITH_IMAGE,                     // narrow layout. image might not be present but expected to be loaded soon
        ANIMATING_TO_IMAGE,             // text only → image
        ANIMATING_TO_TEXT_ONLY,         // image (without image) → text. runs when the image fails to load
        ANIMATING_ONLY_IMAGE            // narrow layout; animating only the image
    }

    enum LayoutType {
        WIDE,
        NARROW
    }

    private AlphaLayout narrowLayout = null;
    private AlphaLayout wideLayout = null;

    private Spannable text = null;
    private Bitmap image = null;
    private Target target;

    private State state = State.TEXT_ONLY;

    private static int counter = 0;

    public LineView(Context context) {
        this(context, null);
    }

    public LineView(Context context, AttributeSet attrs) {
        super(context, attrs);
        // setLayerType(LAYER_TYPE_HARDWARE, null);
        kitty.setPrefix(String.valueOf(counter++));
    }

    private void reset() {
        text = null;
        wideLayout = narrowLayout = null;
        image = null;
        animatedValue = 0f;
        firstDrawAt = HAVE_NOT_DRAWN;
        state = State.TEXT_ONLY;
        if (animator != null) animator.cancel();
        animator = null;
        Glide.with(getContext()).clear(target);     // will call the listener!
        target = null;
    }

    public void setText(Line line) {
        Strategy.Url url = null;
        Cache.Info info = null;

        if (text == line.getSpannable() && getCurrentLayout().getPaint() == P.textPaint) return;
        reset();

        text = line.getSpannable();

        if (Engine.isEnabledAtAll() && Engine.isEnabledForLocation(Engine.Location.CHAT) && Engine.isEnabledForLine(line)) {
            List<Strategy.Url> candidates = Engine.getPossibleMediaCandidates(getUrls(), Strategy.Size.SMALL);
            if (!candidates.isEmpty()) {
                url = candidates.get(0);
                info = Cache.info(url);
            }
        }

        setLayout(info == Cache.Info.FETCHED_RECENTLY ? LayoutType.NARROW : LayoutType.WIDE);
        invalidate();

        if (url == null || info == Cache.Info.FAILED_RECENTLY) return;

        ensureLayout(LayoutType.NARROW);
        target = Glide.with(getContext())
                .asBitmap()
                .apply(Engine.defaultRequestOptions)
                .listener(Cache.bitmapListener)
                .load(url)
                .onlyRetrieveFromCache(Engine.isDisabledForCurrentNetwork())
                .into(new Target(thumbnailWidth, getThumbnailHeight()));
    }

    private class Target extends CustomTarget<Bitmap> {
        Target(int width, int height) {
            super(width, height);
        }

        @Override public void onResourceReady(@NonNull Bitmap resource, @Nullable Transition transition) {
            setImage(resource);
        }

        @Override public void onLoadCleared(@Nullable Drawable placeholder) {
            setImage(null);
        }

        // the request seems to be attempted once again on minimizing/restoring the app. to avoid
        // that, clear target soon, but not on current thread as the library doesn't allow it
        @Override public void onLoadFailed(@Nullable Drawable errorDrawable) {
            Target local = target;
            Weechat.runOnMainThread(() -> Glide.with(getContext()).clear(local));
            setImage(null);
        }
    }

    private void setImage(@Nullable Bitmap image) {
        if (this.image == image && !(image == null && state == State.WITH_IMAGE)) return;
        this.image = image;
        if (text == null) return;   // text can be null if called from reset(), in this case don't proceed
        if (shouldAnimateChange()) {
            animateChange();
        } else {
            setLayout(image == null ? LayoutType.WIDE : LayoutType.NARROW);
            invalidate();
        }
    }

    private AlphaLayout getCurrentLayout() {
        return (state == State.TEXT_ONLY) ? wideLayout : narrowLayout;
    }

    private void ensureLayout(LayoutType layoutType) {
        if (layoutType == LayoutType.WIDE && wideLayout == null) wideLayout = AlphaLayout.make(text, P.weaselWidth);
        if (layoutType == LayoutType.NARROW && narrowLayout == null) narrowLayout = AlphaLayout.make(text, P.weaselWidth - Config.thumbnailAreaWidth);
    }

    private void setLayout(LayoutType layoutType) {
        ensureLayout(layoutType);
        this.state = layoutType == LayoutType.WIDE ? State.TEXT_ONLY : State.WITH_IMAGE;
        if (getViewHeight(State.TEXT_ONLY) != getViewHeight(State.WITH_IMAGE)) requestLayout();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    @Override protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        setMeasuredDimension(P.weaselWidth, getViewHeight(state));
    }

    private int getViewHeight(State state) {
        if (state == State.TEXT_ONLY)
            return wideLayout == null ? 0 : wideLayout.getHeight();
        if (state == State.WITH_IMAGE || state == State.ANIMATING_ONLY_IMAGE)
            return Math.max(narrowLayout == null ? 0 : narrowLayout.getHeight(), Config.thumbnailAreaMinHeight);

        int wideHeight = getViewHeight(State.TEXT_ONLY);
        int narrowHeight = getViewHeight(State.WITH_IMAGE);
        return wideHeight + ((int) ((narrowHeight - wideHeight) * animatedValue));
    }

    final private Paint imagePaint = new Paint();
    @Override protected void onDraw(Canvas canvas) {
        if (state == State.ANIMATING_TO_IMAGE || state == State.ANIMATING_TO_TEXT_ONLY) {
            wideLayout.draw(canvas, 1f - animatedValue);
            narrowLayout.draw(canvas, animatedValue);
        } else if (state == State.ANIMATING_ONLY_IMAGE) {
            narrowLayout.draw(canvas);
        } else {
            getCurrentLayout().draw(canvas);
        }
        if (image != null) {
            Paint paint = null;
            if (state == State.ANIMATING_TO_IMAGE || state == State.ANIMATING_ONLY_IMAGE) {
                paint = imagePaint;
                paint.setAlpha((int) (animatedValue * 255));
            }
            canvas.drawBitmap(image,
                    P.weaselWidth - thumbnailWidth - THUMBNAIL_HORIZONTAL_MARGIN,
                    THUMBNAIL_VERTICAL_MARGIN, paint);
        }
        if (firstDrawAt == HAVE_NOT_DRAWN) firstDrawAt = System.currentTimeMillis();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    // AS suggests calling performClick(), which does stuff like playing tap sound and accessibility,
    // but LinkMovementMethod doesn't seem to be calling any methods like that, so we are not doing
    // it either. on long click, we call performLongClick(), which also does haptic feedback.
    // we are consuming all touch events mostly because it works well. perhaps only handle up/down?
    @SuppressLint("ClickableViewAccessibility")
    @Override public boolean onTouchEvent(MotionEvent event) {
        gestureDetector.onTouchEvent(event);
        return true;
    }

    final GestureDetector gestureDetector = new GestureDetector(Weechat.applicationContext,
            new GestureDetector.SimpleOnGestureListener() {
        @Override public void onLongPress(MotionEvent event) {
            performLongClick();
        }

        // see android.text.method.LinkMovementMethod.onTouchEvent
        @Override public boolean onSingleTapUp(MotionEvent event) {
            int line = getCurrentLayout().getLineForVertical((int) event.getY());
            int off = getCurrentLayout().getOffsetForHorizontal(line, event.getX());
            ClickableSpan[] links = text.getSpans(off, off, ClickableSpan.class);
            if (links.length > 0) {
                links[0].onClick(LineView.this);
                return true;
            }
            return false;
        }
    });

    public URLSpan[] getUrls() {
        return text.getSpans(0, text.length(), URLSpan.class);
    }

    private int getThumbnailHeight() {
        int height = narrowLayout.getHeight() - THUMBNAIL_VERTICAL_MARGIN * 2;
        if (height < thumbnailMinHeight) height = thumbnailMinHeight;
        if (height > thumbnailMaxHeight) height = thumbnailMaxHeight;
        return height;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////// animation
    ////////////////////////////////////////////////////////////////////////////////////////////////

    // a value that is used to animate view size and the crossfade. 0f corresponds to the initial
    // text-only layout, 1f to the layout with image. can go both directions
    private float animatedValue = 0f;

    // time in ms when the current text have been first drawn on canvas
    private long firstDrawAt = HAVE_NOT_DRAWN;

    private @Nullable ValueAnimator animator;
    final private static long HAVE_NOT_DRAWN = -1;

    private void animateChange() {
        assertThat(state).isAnyOf(State.WITH_IMAGE, State.TEXT_ONLY);

        boolean toImage = image != null;
        if (toImage) {
            state = state == State.WITH_IMAGE ? State.ANIMATING_ONLY_IMAGE : State.ANIMATING_TO_IMAGE;
            ensureLayout(LayoutType.NARROW);
            narrowLayout.ensureBitmap();
        } else {
            state = State.ANIMATING_TO_TEXT_ONLY;
            ensureLayout(LayoutType.WIDE);
            wideLayout.ensureBitmap();
        }

        boolean needsRelayout = getViewHeight(state) != getViewHeight(State.WITH_IMAGE);
        float from = toImage ? 0f : 1f;
        float to = toImage ? 1f : 0f;
        animator = ValueAnimator.ofFloat(from, to).setDuration(ANIMATION_DURATION);
        animator.addUpdateListener(animation -> {
            animatedValue = (float) animation.getAnimatedValue();
            if (animatedValue == to) {
                state = toImage ? State.WITH_IMAGE : State.TEXT_ONLY;
                narrowLayout.clearBitmap();
                if (wideLayout != null) wideLayout.clearBitmap();
            }
            if (needsRelayout) requestLayout();
            invalidate();
        });
        animator.start();
    }

    public void cancelAnimation() {
        if (animator != null) animator.end();
    }

    // animate layout change—but only if the view is visible and has been visible for some minimum
    // period of time, to avoid too much animation. see https://stackoverflow.com/a/12428154/1449683
    final private Rect _rect = new Rect();
    private boolean shouldAnimateChange() {
        if (!isAttachedToWindow() || getParent() == null)
             return false;
        ((View) getParent()).getHitRect(_rect);
        if (!getLocalVisibleRect(_rect))
            return false;
        long time = System.currentTimeMillis();
        return firstDrawAt != HAVE_NOT_DRAWN && time - firstDrawAt > 50;
    }
}