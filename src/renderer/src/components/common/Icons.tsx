interface IconProps {
  size?: number;
  className?: string;
  color?: string;
}

export const TerminalIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M4 17l6-6-6-6M12 19h8"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const NetworkIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <path
      d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const ShieldIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const LockIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" stroke={color} strokeWidth="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const UnlockIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" stroke={color} strokeWidth="2" />
    <path d="M7 11V7a5 5 0 0 1 9.9-1" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const SearchIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="11" cy="11" r="8" stroke={color} strokeWidth="2" />
    <path d="M21 21l-4.35-4.35" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const WarningIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <line x1="12" y1="9" x2="12" y2="13" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <circle cx="12" cy="17" r="0.5" fill={color} />
  </svg>
);

export const CheckIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M20 6L9 17l-5-5"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const XIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <line x1="18" y1="6" x2="6" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="6" y1="6" x2="18" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const AlertIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <line x1="12" y1="8" x2="12" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <circle cx="12" cy="16" r="0.5" fill={color} />
  </svg>
);

export const DangerIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <line x1="15" y1="9" x2="9" y2="15" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="9" y1="9" x2="15" y2="15" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const InfoIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <line x1="12" y1="16" x2="12" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <circle cx="12" cy="8" r="0.5" fill={color} />
  </svg>
);

export const CodeIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="16 18 22 12 16 6"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <polyline
      points="8 6 2 12 8 18"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const DatabaseIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <ellipse cx="12" cy="5" rx="9" ry="3" stroke={color} strokeWidth="2" />
    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" stroke={color} strokeWidth="2" />
    <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" stroke={color} strokeWidth="2" />
  </svg>
);

export const KeyIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ServerIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="2" width="20" height="8" rx="2" stroke={color} strokeWidth="2" />
    <rect x="2" y="14" width="20" height="8" rx="2" stroke={color} strokeWidth="2" />
    <line x1="6" y1="6" x2="6.01" y2="6" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="6" y1="18" x2="6.01" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const BugIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 2a4 4 0 0 0-4 4h8a4 4 0 0 0-4-4zm0 0v4m-4 0H4m4 0v8c0 3 2 5 4 5s4-2 4-5V6m0 0h4M8 10H4m16 0h-4M8 14H4m16 0h-4m-4 5v3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const TargetIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <circle cx="12" cy="12" r="6" stroke={color} strokeWidth="2" />
    <circle cx="12" cy="12" r="2" stroke={color} strokeWidth="2" />
  </svg>
);

export const ZapIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polygon
      points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const PlayIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polygon
      points="5 3 19 12 5 21 5 3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const LoadingIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const CopyIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="9" y="9" width="13" height="13" rx="2" stroke={color} strokeWidth="2" />
    <path
      d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const DownloadIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const TrashIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="3 6 5 6 21 6"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const RefreshIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M1 4v6h6M23 20v-6h-6"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const FileIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <polyline
      points="13 2 13 9 20 9"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const HashIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <line x1="4" y1="9" x2="20" y2="9" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="4" y1="15" x2="20" y2="15" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="10" y1="3" x2="8" y2="21" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="16" y1="3" x2="14" y2="21" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const EyeIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke={color} strokeWidth="2" />
    <circle cx="12" cy="12" r="3" stroke={color} strokeWidth="2" />
  </svg>
);

export const GlobeIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <line x1="2" y1="12" x2="22" y2="12" stroke={color} strokeWidth="2" />
    <path
      d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const PlugIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M6 3v3M18 3v3M9 8h6M9 8v13a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V8M9 8H6m9 0h3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ClockIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <polyline
      points="12 6 12 12 16 14"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const MaskIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2z"
      stroke={color}
      strokeWidth="2"
    />
    <circle cx="8" cy="10" r="1.5" fill={color} />
    <circle cx="16" cy="10" r="1.5" fill={color} />
    <path d="M8 15c1 2 3 3 4 3s3-1 4-3" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const PaletteIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"
      stroke={color}
      strokeWidth="2"
    />
    <circle cx="6.5" cy="11.5" r="1.5" fill={color} />
    <circle cx="9.5" cy="7.5" r="1.5" fill={color} />
    <circle cx="14.5" cy="7.5" r="1.5" fill={color} />
    <circle cx="17.5" cy="11.5" r="1.5" fill={color} />
  </svg>
);

export const InjectionIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M4.5 16.5l3.5-3.5m5 3l1.5 1.5 6-6-3-3-6 6m0 0l-1.5 1.5m0 0L8 14M2 20l2-2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M20 7l-3-3M16 10l-4-4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const AlarmIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="13" r="8" stroke={color} strokeWidth="2" />
    <path
      d="M12 9v4l2 2M5 3L2 6m20-3l-3 3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const RepeatIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="17 1 21 5 17 9"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M3 11V9a4 4 0 0 1 4-4h14"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <polyline
      points="7 23 3 19 7 15"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M21 13v2a4 4 0 0 1-4 4H3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const CompressIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="4 14 10 14 10 20"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <polyline
      points="20 10 14 10 14 4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <line x1="14" y1="10" x2="21" y2="3" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="3" y1="21" x2="10" y2="14" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const SparklesIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 3v3m0 12v3M3 12h3m12 0h3M6.3 6.3l2.1 2.1m7.2 7.2l2.1 2.1M6.3 17.7l2.1-2.1m7.2-7.2l2.1-2.1"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const LinkIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const DiffIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="3" width="18" height="18" rx="2" stroke={color} strokeWidth="2" />
    <line x1="9" y1="3" x2="9" y2="21" stroke={color} strokeWidth="2" />
    <line x1="14" y1="8" x2="16" y2="8" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="14" y1="12" x2="16" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="14" y1="16" x2="16" y2="16" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const PackageIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
      stroke={color}
      strokeWidth="2"
    />
    <polyline
      points="3.27 6.96 12 12.01 20.73 6.96"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <line x1="12" y1="22.08" x2="12" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const TextIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="4 7 4 4 20 4 20 7"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <line x1="9" y1="20" x2="15" y2="20" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="12" y1="4" x2="12" y2="20" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const RadioIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="2" fill={color} />
    <path
      d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ShellIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="4 17 10 11 4 5"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <line x1="12" y1="19" x2="20" y2="19" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const DocumentIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
      stroke={color}
      strokeWidth="2"
    />
    <polyline points="14 2 14 8 20 8" stroke={color} strokeWidth="2" />
    <line x1="16" y1="13" x2="8" y2="13" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="16" y1="17" x2="8" y2="17" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="10" y1="9" x2="8" y2="9" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const IdIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="6" width="20" height="12" rx="2" stroke={color} strokeWidth="2" />
    <circle cx="8" cy="12" r="2" stroke={color} strokeWidth="2" />
    <line x1="14" y1="10" x2="18" y2="10" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="14" y1="14" x2="18" y2="14" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const WebIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <path
      d="M12 2v20M2 12h20M8 4c-2 3-2 9 0 16M16 4c2 3 2 9 0 16"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const BellIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const EncryptIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke={color} strokeWidth="2" />
    <path
      d="M7 11V7a5 5 0 0 1 10 0v4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <circle cx="12" cy="16" r="1" fill={color} />
  </svg>
);

export const FolderIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const TicketIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M2 9a3 3 0 0 1 0-6h20a3 3 0 0 1 0 6M2 9v6m20-6v6M2 15a3 3 0 0 0 0 6h20a3 3 0 0 0 0-6"
      stroke={color}
      strokeWidth="2"
    />
    <line x1="13" y1="6" x2="13" y2="9" stroke={color} strokeWidth="2" strokeLinecap="round" />
    <line x1="13" y1="15" x2="13" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const SlugIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path d="M4 7h16M4 12h10M4 17h13" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const MarkdownIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="5" width="20" height="14" rx="2" stroke={color} strokeWidth="2" />
    <path
      d="M6 15V9l2 2 2-2v6M18 13l-2-2v4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const EncodeIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
      stroke={color}
      strokeWidth="2"
    />
    <circle cx="12" cy="12" r="3" stroke={color} strokeWidth="2" />
  </svg>
);

export const RegexIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M3 12h2m14 0h2M7 8l-4 4 4 4m10-8l4 4-4 4"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <circle cx="12" cy="12" r="2" fill={color} />
  </svg>
);

export const PasswordIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" stroke={color} strokeWidth="2" />
    <circle cx="8" cy="16" r="1" fill={color} />
    <circle cx="12" cy="16" r="1" fill={color} />
    <circle cx="16" cy="16" r="1" fill={color} />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const LoremIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path d="M3 7h18M3 12h18M3 17h12" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const CertificateIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M4 7V4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-3"
      stroke={color}
      strokeWidth="2"
    />
    <circle cx="8" cy="17" r="3" stroke={color} strokeWidth="2" />
    <path
      d="M8 14v7M6 19l2 2 2-2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const UploadIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const JsonIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M7 8H5a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h2M17 8h2a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
    <line x1="10" y1="12" x2="14" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const OAuthIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="3" stroke={color} strokeWidth="2" />
    <path d="M12 1v6m0 6v10M1 12h6m6 0h10" stroke={color} strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const DiceIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="3" width="18" height="18" rx="2" stroke={color} strokeWidth="2" />
    <circle cx="8" cy="8" r="1" fill={color} />
    <circle cx="16" cy="8" r="1" fill={color} />
    <circle cx="12" cy="12" r="1" fill={color} />
    <circle cx="8" cy="16" r="1" fill={color} />
    <circle cx="16" cy="16" r="1" fill={color} />
  </svg>
);

export const HttpIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="7" width="20" height="10" rx="2" stroke={color} strokeWidth="2" />
    <path d="M22 12H2M8 7v10m8-10v10" stroke={color} strokeWidth="2" />
  </svg>
);

export const EntityIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"
      stroke={color}
      strokeWidth="2"
    />
    <path
      d="M14 2v6h6M10 13h4M10 17h4M10 9h1"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const WhoIsIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 11c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zM12 13c-4 0-7 2-7 5v3h14v-3c0-3-3-5-7-5z"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const UptimeIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="22 12 18 12 15 21 9 3 6 12 2 12"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const SubdomainIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="2" />
    <path
      d="M12 2c-2.5 3-2.5 7 0 10s2.5 7 0 10M12 2c2.5 3 2.5 7 0 10s-2.5 7 0 10M2 12h20"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
);

export const FolderOpenIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2v11z"
      stroke={color}
      strokeWidth="2"
      fill="none"
    />
    <path d="M2 10h20" stroke={color} strokeWidth="2" />
  </svg>
);

export const ImageFileIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="3" y="3" width="18" height="18" rx="2" stroke={color} strokeWidth="2" />
    <circle cx="8.5" cy="8.5" r="1.5" fill={color} />
    <path
      d="M21 15l-5-5L5 21"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ConfigFileIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <circle cx="12" cy="12" r="3" stroke={color} strokeWidth="2" />
    <path
      d="M12 1v3m0 14v3M4.22 4.22l2.12 2.12m11.32 11.32l2.12 2.12M1 12h3m14 0h3M4.22 19.78l2.12-2.12m11.32-11.32l2.12-2.12"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const PythonFileIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M12 2c-2 0-3 1-3 3v2h6V6h2c2 0 3 1 3 3v6c0 2-1 3-3 3h-2v-2H9v3c0 2 1 3 3 3h3c2 0 3-1 3-3v-2h-6v1H7c-2 0-3-1-3-3V9c0-2 1-3 3-3h2V4c0-2 1-3 3-3z"
      stroke={color}
      strokeWidth="1.5"
    />
    <circle cx="8" cy="9" r="1" fill={color} />
    <circle cx="16" cy="15" r="1" fill={color} />
  </svg>
);

export const JavaScriptFileIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="2" width="20" height="20" rx="2" stroke={color} strokeWidth="2" />
    <path
      d="M13 18c0 1.1-.9 2-2 2s-2-.9-2-2v-5m6 5c0 1.1.9 2 2 2s2-.9 2-2-1-2-2-2h-2"
      stroke={color}
      strokeWidth="1.5"
      strokeLinecap="round"
    />
  </svg>
);

export const TypeScriptFileIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="2" width="20" height="20" rx="2" stroke={color} strokeWidth="2" />
    <path
      d="M12 8v8M8 12h8M17 16c0 1.1-.9 2-2 2s-2-.9-2-2v-2"
      stroke={color}
      strokeWidth="1.5"
      strokeLinecap="round"
    />
  </svg>
);

export const MarkdownFileIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <rect x="2" y="4" width="20" height="16" rx="2" stroke={color} strokeWidth="2" />
    <path
      d="M6 15V9l2 2 2-2v6M16 11l2 2 2-2M18 13v2"
      stroke={color}
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const JsonFileIcon = ({ size = 16, className = '', color = 'currentColor' }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <path
      d="M6 4h3a2 2 0 0 1 2 2v3a2 2 0 0 0 2 2 2 2 0 0 0-2 2v3a2 2 0 0 1-2 2H6M18 4h-3a2 2 0 0 0-2 2v3a2 2 0 0 1-2 2 2 2 0 0 1 2 2v3a2 2 0 0 0 2 2h3"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const ChevronRightIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="9 18 15 12 9 6"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ChevronDownIcon = ({
  size = 16,
  className = '',
  color = 'currentColor',
}: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
    <polyline
      points="6 9 12 15 18 9"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);


export const RubyFileIcon = () => <span style={{ color: '#CC342D', fontSize: '14px' }}>💎</span>;
export const SwiftFileIcon = () => <span style={{ color: '#FA7343', fontSize: '14px' }}>🦅</span>;
export const KotlinFileIcon = () => <span style={{ color: '#7F52FF', fontSize: '14px' }}>🅚</span>;
export const ScalaFileIcon = () => <span style={{ color: '#DC322F', fontSize: '14px' }}>🅢</span>;
export const RFileIcon = () => <span style={{ color: '#276DC3', fontSize: '14px' }}>📊</span>;
export const LuaFileIcon = () => <span style={{ color: '#000080', fontSize: '14px' }}>🌙</span>;
export const PerlFileIcon = () => <span style={{ color: '#0298C3', fontSize: '14px' }}>🐪</span>;
export const HaskellFileIcon = () => <span style={{ color: '#5D4F85', fontSize: '14px' }}>λ</span>;
export const ElixirFileIcon = () => <span style={{ color: '#4B275F', fontSize: '14px' }}>💧</span>;
export const DartFileIcon = () => <span style={{ color: '#0175C2', fontSize: '14px' }}>🎯</span>;
export const JuliaFileIcon = () => <span style={{ color: '#9558B2', fontSize: '14px' }}>📐</span>;
export const ClojureFileIcon = () => <span style={{ color: '#5881D8', fontSize: '14px' }}>🔵</span>;
export const ErlangFileIcon = () => <span style={{ color: '#A90533', fontSize: '14px' }}>📞</span>;
export const FSharpFileIcon = () => <span style={{ color: '#378BBA', fontSize: '14px' }}>F#</span>;
export const OCamlFileIcon = () => <span style={{ color: '#EE6A1A', fontSize: '14px' }}>🐫</span>;
export const NimFileIcon = () => <span style={{ color: '#FFE953', fontSize: '14px' }}>👑</span>;
export const CrystalFileIcon = () => <span style={{ color: '#000000', fontSize: '14px' }}>💎</span>;
export const ZigFileIcon = () => <span style={{ color: '#F7A41D', fontSize: '14px' }}>⚡</span>;
export const VFileIcon = () => <span style={{ color: '#5D87BF', fontSize: '14px' }}>🅥</span>;
export const AssemblyFileIcon = () => (
  <span style={{ color: '#6E4C13', fontSize: '14px' }}>⚙️</span>
);
export const ObjectiveCFileIcon = () => (
  <span style={{ color: '#438EFF', fontSize: '14px' }}>🍎</span>
);
export const FortranFileIcon = () => <span style={{ color: '#734F96', fontSize: '14px' }}>🔬</span>;
export const CobolFileIcon = () => <span style={{ color: '#005CA5', fontSize: '14px' }}>💼</span>;
export const PascalFileIcon = () => <span style={{ color: '#E3F171', fontSize: '14px' }}>🎓</span>;
export const LispFileIcon = () => <span style={{ color: '#3FB68B', fontSize: '14px' }}>🔄</span>;
export const SchemeFileIcon = () => <span style={{ color: '#1E4AEC', fontSize: '14px' }}>🔵</span>;
export const RacketFileIcon = () => <span style={{ color: '#9F1D20', fontSize: '14px' }}>🎾</span>;
export const PrologFileIcon = () => <span style={{ color: '#74283C', fontSize: '14px' }}>🧩</span>;
export const VerilogFileIcon = () => <span style={{ color: '#B2B7F8', fontSize: '14px' }}>🔌</span>;
export const VHDLFileIcon = () => <span style={{ color: '#543978', fontSize: '14px' }}>🔌</span>;
export const JavaFileIcon = () => <span style={{ color: '#B07219', fontSize: '14px' }}>☕</span>;
export const CppFileIcon = () => <span style={{ color: '#F34B7D', fontSize: '14px' }}>C++</span>;
export const CFileIcon = () => <span style={{ color: '#555555', fontSize: '14px' }}>🅲</span>;
export const CSharpFileIcon = () => <span style={{ color: '#178600', fontSize: '14px' }}>C#</span>;
export const GoFileIcon = () => <span style={{ color: '#00ADD8', fontSize: '14px' }}>🐹</span>;
export const RustFileIcon = () => <span style={{ color: '#DEA584', fontSize: '14px' }}>🦀</span>;
export const PHPFileIcon = () => <span style={{ color: '#4F5D95', fontSize: '14px' }}>🐘</span>;


export const CSSFileIcon = () => <span style={{ color: '#1572B6', fontSize: '14px' }}>🎨</span>;
export const SCSSFileIcon = () => <span style={{ color: '#CC6699', fontSize: '14px' }}>💅</span>;
export const SassFileIcon = () => <span style={{ color: '#CC6699', fontSize: '14px' }}>💅</span>;
export const LessFileIcon = () => <span style={{ color: '#1D365D', fontSize: '14px' }}>🎨</span>;
export const StylusFileIcon = () => <span style={{ color: '#FF6347', fontSize: '14px' }}>🎨</span>;
export const PostCSSFileIcon = () => <span style={{ color: '#DD3A0A', fontSize: '14px' }}>🎨</span>;


export const HTMLFileIcon = () => <span style={{ color: '#E34C26', fontSize: '14px' }}>🌐</span>;
export const XMLFileIcon = () => <span style={{ color: '#E37933', fontSize: '14px' }}>📄</span>;
export const SVGFileIcon = () => <span style={{ color: '#FFB13B', fontSize: '14px' }}>🎨</span>;
export const VueFileIcon = () => <span style={{ color: '#42B883', fontSize: '14px' }}>🔷</span>;
export const SvelteFileIcon = () => <span style={{ color: '#FF3E00', fontSize: '14px' }}>🔥</span>;
export const AstroFileIcon = () => <span style={{ color: '#FF5D01', fontSize: '14px' }}>🚀</span>;
export const HandlebarsFileIcon = () => (
  <span style={{ color: '#F0772B', fontSize: '14px' }}>📝</span>
);
export const MustacheFileIcon = () => (
  <span style={{ color: '#F0772B', fontSize: '14px' }}>📝</span>
);
export const EJSFileIcon = () => <span style={{ color: '#B4CA65', fontSize: '14px' }}>📝</span>;
export const PugFileIcon = () => <span style={{ color: '#A86454', fontSize: '14px' }}>🐶</span>;


export const DockerFileIcon = () => <span style={{ color: '#2496ED', fontSize: '14px' }}>🐳</span>;
export const MakefileIcon = () => <span style={{ color: '#427819', fontSize: '14px' }}>🔨</span>;
export const CMakeIcon = () => <span style={{ color: '#064F8C', fontSize: '14px' }}>🔧</span>;
export const TerraformFileIcon = () => (
  <span style={{ color: '#7B42BC', fontSize: '14px' }}>🏗️</span>
);
export const AnsibleFileIcon = () => <span style={{ color: '#EE0000', fontSize: '14px' }}>⚙️</span>;
export const KubernetesFileIcon = () => (
  <span style={{ color: '#326CE5', fontSize: '14px' }}>☸️</span>
);
export const NginxFileIcon = () => <span style={{ color: '#009639', fontSize: '14px' }}>🌐</span>;
export const ApacheFileIcon = () => <span style={{ color: '#D22128', fontSize: '14px' }}>🪶</span>;
export const GitFileIcon = () => <span style={{ color: '#F05032', fontSize: '14px' }}>🔀</span>;
export const GitIgnoreFileIcon = () => (
  <span style={{ color: '#F05032', fontSize: '14px' }}>🚫</span>
);
export const EditorConfigFileIcon = () => (
  <span style={{ color: '#FEFEFE', fontSize: '14px' }}>⚙️</span>
);
export const PrettierFileIcon = () => (
  <span style={{ color: '#F7B93E', fontSize: '14px' }}>✨</span>
);
export const ESLintFileIcon = () => <span style={{ color: '#4B32C3', fontSize: '14px' }}>🔍</span>;
export const BabelFileIcon = () => <span style={{ color: '#F9DC3E', fontSize: '14px' }}>🔄</span>;
export const WebpackFileIcon = () => <span style={{ color: '#8DD6F9', fontSize: '14px' }}>📦</span>;
export const ViteFileIcon = () => <span style={{ color: '#646CFF', fontSize: '14px' }}>⚡</span>;
export const RollupFileIcon = () => <span style={{ color: '#EC4A3F', fontSize: '14px' }}>📦</span>;
export const PackageJsonFileIcon = () => (
  <span style={{ color: '#CB3837', fontSize: '14px' }}>📦</span>
);
export const YarnLockFileIcon = () => (
  <span style={{ color: '#2C8EBB', fontSize: '14px' }}>🧶</span>
);
export const CargoFileIcon = () => <span style={{ color: '#DEA584', fontSize: '14px' }}>📦</span>;
export const GemfileIcon = () => <span style={{ color: '#CC342D', fontSize: '14px' }}>💎</span>;
export const RequirementsFileIcon = () => (
  <span style={{ color: '#3776AB', fontSize: '14px' }}>📋</span>
);
export const GoModFileIcon = () => <span style={{ color: '#00ADD8', fontSize: '14px' }}>📦</span>;
export const GradleFileIcon = () => <span style={{ color: '#02303A', fontSize: '14px' }}>🐘</span>;
export const YAMLFileIcon = () => <span style={{ color: '#CB171E', fontSize: '14px' }}>📄</span>;
export const TOMLFileIcon = () => <span style={{ color: '#9C4121', fontSize: '14px' }}>📄</span>;
export const INIFileIcon = () => <span style={{ color: '#6D7E8A', fontSize: '14px' }}>⚙️</span>;
export const EnvFileIcon = () => <span style={{ color: '#ECD53F', fontSize: '14px' }}>🔐</span>;


export const GraphQLFileIcon = () => <span style={{ color: '#E10098', fontSize: '14px' }}>◈</span>;
export const ProtobufFileIcon = () => (
  <span style={{ color: '#4285F4', fontSize: '14px' }}>📡</span>
);
export const AvroFileIcon = () => <span style={{ color: '#0062B1', fontSize: '14px' }}>📊</span>;
export const ParquetFileIcon = () => <span style={{ color: '#50ABF1', fontSize: '14px' }}>📊</span>;
export const CSVFileIcon = () => <span style={{ color: '#73BF69', fontSize: '14px' }}>📈</span>;
export const ExcelFileIcon = () => <span style={{ color: '#217346', fontSize: '14px' }}>📊</span>;
export const SQLFileIcon = () => <span style={{ color: '#E38C00', fontSize: '14px' }}>🗄️</span>;
export const SQLiteFileIcon = () => <span style={{ color: '#003B57', fontSize: '14px' }}>💾</span>;
export const MongoDBFileIcon = () => <span style={{ color: '#47A248', fontSize: '14px' }}>🍃</span>;
export const RedisFileIcon = () => <span style={{ color: '#DC382D', fontSize: '14px' }}>⚡</span>;


export const ReadmeFileIcon = () => <span style={{ color: '#4A90E2', fontSize: '14px' }}>📖</span>;
export const LicenseFileIcon = () => <span style={{ color: '#00ADD8', fontSize: '14px' }}>⚖️</span>;
export const ChangelogFileIcon = () => (
  <span style={{ color: '#8B8B8B', fontSize: '14px' }}>📋</span>
);
export const ContributingFileIcon = () => (
  <span style={{ color: '#6CC644', fontSize: '14px' }}>🤝</span>
);
export const CodeOfConductFileIcon = () => (
  <span style={{ color: '#FF6B6B', fontSize: '14px' }}>📜</span>
);
export const AsciiDocFileIcon = () => (
  <span style={{ color: '#E40046', fontSize: '14px' }}>📄</span>
);
export const ReStructuredTextFileIcon = () => (
  <span style={{ color: '#3A3A3A', fontSize: '14px' }}>📄</span>
);
export const LaTeXFileIcon = () => <span style={{ color: '#008080', fontSize: '14px' }}>📐</span>;
export const OrgModeFileIcon = () => <span style={{ color: '#77AA99', fontSize: '14px' }}>📝</span>;
export const TextFileIcon = () => <span style={{ color: '#89E051', fontSize: '14px' }}>📝</span>;


export const VideoFileIcon = () => <span style={{ color: '#FD971F', fontSize: '14px' }}>🎬</span>;
export const AudioFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🎵</span>;
export const MP4FileIcon = () => <span style={{ color: '#FD971F', fontSize: '14px' }}>🎥</span>;
export const MP3FileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🎵</span>;
export const PNGFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🖼️</span>;
export const JPGFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🖼️</span>;
export const GIFFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🎞️</span>;
export const WebPFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🖼️</span>;
export const ICOFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🔷</span>;
export const TIFFFileIcon = () => <span style={{ color: '#FF6B81', fontSize: '14px' }}>🖼️</span>;


export const ZipFileIcon = () => <span style={{ color: '#FFA500', fontSize: '14px' }}>📦</span>;
export const TarFileIcon = () => <span style={{ color: '#8B4513', fontSize: '14px' }}>📦</span>;
export const GzFileIcon = () => <span style={{ color: '#00A0E9', fontSize: '14px' }}>🗜️</span>;
export const RarFileIcon = () => <span style={{ color: '#FF0000', fontSize: '14px' }}>📦</span>;
export const SevenZipFileIcon = () => (
  <span style={{ color: '#0078D7', fontSize: '14px' }}>📦</span>
);
export const BinaryFileIcon = () => <span style={{ color: '#808080', fontSize: '14px' }}>⚙️</span>;
export const ExecutableFileIcon = () => (
  <span style={{ color: '#8B0000', fontSize: '14px' }}>⚡</span>
);
export const PDFFileIcon = () => <span style={{ color: '#F40F02', fontSize: '14px' }}>📕</span>;
export const EPUBFileIcon = () => <span style={{ color: '#6B5B93', fontSize: '14px' }}>📚</span>;
export const DLLFileIcon = () => <span style={{ color: '#4B0082', fontSize: '14px' }}>🔧</span>;


export const BashFileIcon = () => <span style={{ color: '#4EAA25', fontSize: '14px' }}>📜</span>;
export const ZshFileIcon = () => <span style={{ color: '#89E051', fontSize: '14px' }}>📜</span>;
export const FishFileIcon = () => <span style={{ color: '#00D1B2', fontSize: '14px' }}>🐟</span>;
export const PowerShellFileIcon = () => (
  <span style={{ color: '#012456', fontSize: '14px' }}>💻</span>
);
export const BatchFileIcon = () => <span style={{ color: '#C1F12E', fontSize: '14px' }}>📜</span>;


export const LockFileIcon = () => <span style={{ color: '#CB3837', fontSize: '14px' }}>🔒</span>;
export const GitHubActionsFileIcon = () => (
  <span style={{ color: '#2088FF', fontSize: '14px' }}>⚙️</span>
);
export const CircleCIFileIcon = () => (
  <span style={{ color: '#343434', fontSize: '14px' }}>⚙️</span>
);
export const TravisFileIcon = () => <span style={{ color: '#B03939', fontSize: '14px' }}>⚙️</span>;
export const JenkinsFileIcon = () => <span style={{ color: '#D24939', fontSize: '14px' }}>👷</span>;


export const NextJSFileIcon = () => <span style={{ color: '#000000', fontSize: '14px' }}>▲</span>;
export const NuxtFileIcon = () => <span style={{ color: '#00C58E', fontSize: '14px' }}>💚</span>;
export const AngularFileIcon = () => <span style={{ color: '#DD0031', fontSize: '14px' }}>🅰️</span>;
export const ReactFileIcon = () => <span style={{ color: '#61DAFB', fontSize: '14px' }}>⚛️</span>;
export const EmberFileIcon = () => <span style={{ color: '#E04E39', fontSize: '14px' }}>🔥</span>;
