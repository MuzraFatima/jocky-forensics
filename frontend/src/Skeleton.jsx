import React from 'react';

/**
 * Placeholder blocks shown while a screen's code or data loads, so the layout
 * does not jump when the real content arrives.
 */
export function SkeletonBlock({ width = '100%', height = '1rem', radius = '6px', style = {} }) {
  return <div className="skeleton" style={{ width, height, borderRadius: radius, ...style }} aria-hidden="true" />;
}

export function SkeletonRows({ rows = 5 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
      {Array.from({ length: rows }, (_, i) => (
        <SkeletonBlock key={i} height="2.25rem" width={i % 3 === 2 ? '72%' : '100%'} />
      ))}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div role="status" aria-label="Loading" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1.5rem' }}>
      <SkeletonBlock width="38%" height="1.75rem" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        {[0, 1, 2, 3].map((i) => (
          <SkeletonBlock key={i} height="5.5rem" radius="10px" />
        ))}
      </div>
      <SkeletonRows rows={6} />
    </div>
  );
}
