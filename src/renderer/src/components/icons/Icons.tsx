import React from 'react';

interface IconProps {
  size?: number;
  color?: string;
  className?: string;
}

export const FolderIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M1.5 3C1.5 2.72386 1.72386 2.5 2 2.5H6L7.5 4H13.5C13.7761 4 14 4.22386 14 4.5V12.5C14 12.7761 13.7761 13 13.5 13H2C1.72386 13 1.5 12.7761 1.5 12.5V3Z" stroke={color} strokeWidth="1.2" fill="none"/>
  </svg>
);

export const SearchIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="6.5" cy="6.5" r="4" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M9.5 9.5L13.5 13.5" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const GitBranchIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="4" cy="3" r="1.5" stroke={color} strokeWidth="1.2" fill="none"/>
    <circle cx="4" cy="13" r="1.5" stroke={color} strokeWidth="1.2" fill="none"/>
    <circle cx="12" cy="8" r="1.5" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M4 4.5V11.5M4 5C4 5 6 5 8 7C10 9 10.5 8 10.5 8" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const BugIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M8 3C6.5 3 5.5 4 5.5 5.5V8.5C5.5 10 6.5 11 8 11C9.5 11 10.5 10 10.5 8.5V5.5C10.5 4 9.5 3 8 3Z" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M5.5 6H2M10.5 6H14M5.5 9H2M10.5 9H14M6.5 3L5 1.5M9.5 3L11 1.5M6 11L4.5 13M10 11L11.5 13" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const ExtensionsIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="2" y="2" width="5" height="5" stroke={color} strokeWidth="1.2" fill="none"/>
    <rect x="9" y="2" width="5" height="5" stroke={color} strokeWidth="1.2" fill="none"/>
    <rect x="2" y="9" width="5" height="5" stroke={color} strokeWidth="1.2" fill="none"/>
    <rect x="9" y="9" width="5" height="5" stroke={color} strokeWidth="1.2" fill="none"/>
  </svg>
);

export const LockIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="3" y="7" width="10" height="7" rx="1" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M5 7V5C5 3.34315 6.34315 2 8 2C9.65685 2 11 3.34315 11 5V7" stroke={color} strokeWidth="1.2" fill="none"/>
    <circle cx="8" cy="10.5" r="1" fill={color}/>
  </svg>
);

export const ToolsIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M6 2L4 4L7 7L5 9L2 6L4 4M10 14L12 12L9 9L11 7L14 10L12 12" stroke={color} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M7 7L9 9" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const RobotIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="3" y="5" width="10" height="8" rx="1.5" stroke={color} strokeWidth="1.2" fill="none"/>
    <circle cx="6" cy="8.5" r="1" fill={color}/>
    <circle cx="10" cy="8.5" r="1" fill={color}/>
    <path d="M6 11H10" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
    <path d="M8 5V2.5M8 2.5C8 2.5 7 2.5 7 1.5M8 2.5C8 2.5 9 2.5 9 1.5" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const SettingsIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="8" r="2" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M8 1V3M8 13V15M15 8H13M3 8H1M12.5 3.5L11 5M5 11L3.5 12.5M12.5 12.5L11 11M5 5L3.5 3.5" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const InfoIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="8" r="6" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M8 7V11M8 5V5.5" stroke={color} strokeWidth="1.5" strokeLinecap="round"/>
  </svg>
);

export const BoltIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M9 2L4 9H8L7 14L12 7H8L9 2Z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" fill="none"/>
  </svg>
);

export const ChevronLeftIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M10 12L6 8L10 4" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const ChevronRightIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M6 4L10 8L6 12" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const ChevronDownIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M4 6L8 10L12 6" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const RefreshIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M2 8C2 4.68629 4.68629 2 8 2C11.3137 2 14 4.68629 14 8C14 11.3137 11.3137 14 8 14C6 14 4.5 13 3.5 11.5M3.5 11.5V14M3.5 11.5H6" stroke={color} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const TerminalIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M2 5L5 8L2 11M7 11H11" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const TrashIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M3 4H13M5 4V3C5 2.44772 5.44772 2 6 2H10C10.5523 2 11 2.44772 11 3V4M6 7V11M10 7V11M4 4L4.5 13C4.5 13.5523 4.94772 14 5.5 14H10.5C11.0523 14 11.5 13.5523 11.5 13L12 4" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const NetworkIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <circle cx="8" cy="8" r="6" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M8 2C8 2 10 5 10 8C10 11 8 14 8 14M8 2C8 2 6 5 6 8C6 11 8 14 8 14M2 8H14M3.5 5H12.5M3.5 11H12.5" stroke={color} strokeWidth="1.2"/>
  </svg>
);

export const ChartIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M2 13V9M6 13V6M10 13V3M14 13V7" stroke={color} strokeWidth="1.5" strokeLinecap="round"/>
  </svg>
);

export const CodeIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M5 4L2 8L5 12M11 4L14 8L11 12M9 2L7 14" stroke={color} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const ShieldIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M8 2L3 4V7C3 10.5 5 13 8 14C11 13 13 10.5 13 7V4L8 2Z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" fill="none"/>
  </svg>
);

export const ComputerIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <rect x="1" y="3" width="14" height="9" rx="1" stroke={color} strokeWidth="1.2" fill="none"/>
    <path d="M5 14H11M8 12V14" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);

export const EditIcon: React.FC<IconProps> = ({ size = 16, color = 'currentColor', className }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" className={className}>
    <path d="M2 11V14H5L13 6L10 3L2 11Z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" fill="none"/>
    <path d="M9 4L12 7" stroke={color} strokeWidth="1.2" strokeLinecap="round"/>
  </svg>
);
