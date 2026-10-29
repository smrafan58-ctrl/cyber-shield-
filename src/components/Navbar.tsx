import React from 'react';
import { Shield, Plus, MessageSquare, LogIn, LogOut, UserCheck } from 'lucide-react';
import { User } from 'firebase/auth';

interface NavbarProps {
  onNewScan: () => void;
  hasResult: boolean;
  isChatOpen: boolean;
  onToggleChat: () => void;
  currentUser: User | null;
  isAuthReady: boolean;
  onGoogleSignIn: () => void;
  onSignOut: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onNewScan,
  hasResult,
  onToggleChat,
  isChatOpen,
  currentUser,
  isAuthReady,
  onGoogleSignIn,
  onSignOut,
}) => {
  return (
    <header className="sticky top-0 z-40 border-b border-[#EEDBC8] bg-[#FBF6EF]/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
        {/* Zone 1: Editorial Brand Mark */}
        <button
          type="button"
          onClick={onNewScan}
          className="group flex items-center gap-3 text-left whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#C85A32] cursor-pointer"
        >
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#E6C9AE] bg-[#FDECD8] text-[#C85A32] group-hover:border-[#C85A32] group-hover:bg-[#C85A32] group-hover:text-white transition-colors">
            <Shield className="h-4.5 w-4.5 shrink-0" aria-hidden="true" />
          </span>
          <div className="flex items-baseline gap-2.5">
            <span className="font-display text-xl font-bold tracking-tight text-[#231710] group-hover:text-[#C85A32] transition-colors">
              CyberShield AI
            </span>
            <span
              aria-hidden="true"
              className="hidden lg:inline text-[#D5B89C] font-light"
            >
              /
            </span>
            <span className="hidden lg:inline text-xs font-medium text-[#7A5C49]">
              URL Threat Studio
            </span>
          </div>
        </button>

        {/* Zone 2: Clean Single-Line Typographic Navigation Links */}
        <nav
          aria-label="Primary navigation"
          className="hidden md:flex items-center gap-8 text-sm font-medium text-[#7A5C49]"
        >
          <button
            type="button"
            onClick={onNewScan}
            className={`py-1 hover:text-[#231710] transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              !hasResult
                ? 'text-[#231710] font-semibold underline underline-offset-8 decoration-[#C85A32] decoration-2'
                : ''
            }`}
          >
            URL Scanner
          </button>
          <button
            type="button"
            onClick={onToggleChat}
            className={`py-1 inline-flex items-center gap-2 hover:text-[#231710] transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              isChatOpen
                ? 'text-[#C85A32] font-semibold underline underline-offset-8 decoration-[#C85A32] decoration-2'
                : ''
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
            <span>AI Security Advisor</span>
          </button>
        </nav>

        {/* Zone 3: Auth & Primary Action */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onToggleChat}
            className={`md:hidden inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              isChatOpen
                ? 'border-[#C85A32] bg-[#FDECD8] text-[#231710]'
                : 'border-[#EEDBC8] bg-[#FFFDF9] text-[#231710] hover:bg-[#FDF5EB]'
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
            <span>Advisor</span>
          </button>

          {isAuthReady && (
            <>
              {currentUser ? (
                <div className="flex items-center gap-2">
                  <span
                    data-testid="authenticated-user-label"
                    className="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium text-[#4A3528] truncate max-w-[160px]"
                    title={currentUser.displayName || currentUser.email || 'Signed in'}
                  >
                    <UserCheck className="h-3.5 w-3.5 text-emerald-700 shrink-0" aria-hidden="true" />
                    <span className="truncate">
                      {currentUser.displayName || currentUser.email?.split('@')[0] || 'Analyst'}
                    </span>
                  </span>
                  <button
                    type="button"
                    data-testid="user-signout-button"
                    onClick={onSignOut}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[#E6C9AE] bg-[#FFFDF9] px-3 py-2 text-xs font-medium text-[#4A3528] hover:border-[#C85A32] hover:bg-[#FDECD8] hover:text-[#231710] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <LogOut className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
                    <span>Sign Out</span>
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  data-testid="google-signin-button"
                  onClick={onGoogleSignIn}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[#E6C9AE] bg-[#FFFDF9] px-3.5 py-2.5 text-xs font-semibold text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <LogIn className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
                  <span>Sign in with Google</span>
                </button>
              )}
            </>
          )}

          <button
            type="button"
            onClick={onNewScan}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-warm-cta rounded-lg transition-all whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#C85A32] cursor-pointer shadow-xs"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{hasResult ? 'Scan Another URL' : 'New URL Scan'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};


