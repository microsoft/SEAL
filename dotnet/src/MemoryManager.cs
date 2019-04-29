// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Memory Manager Profile Options used in MemoryManager.GetPool method
    /// </summary>
    public enum MMProfOpt : ulong
    {
        /// <summary>
        /// Use default profile
        /// </summary>
        Default = 0,

        /// <summary>
        /// Force use of the Global profile
        /// </summary>
        ForceGlobal = 1,

        /// <summary>
        /// Force use of a New profile
        /// </summary>
        ForceNew = 2,

        /// <summary>
        /// Force use of the Thread Local profile
        /// </summary>
        ForceThreadLocal = 4
    }

    /// <summary>
    /// The MemoryManager class can be used to create instances of MemoryPoolHandle
    /// based on a given "profile". A profile is implemented by inheriting from the
    /// MMProf class (pure virtual) and encapsulates internal logic for deciding which
    /// memory pool to use.
    /// </summary>
    public static class MemoryManager
    {
        /// <summary>
        /// Static initialization of MemoryManager
        /// </summary>
        static MemoryManager()
        {
            // The default profile is Global
            profile_ = new MMProfGlobal();
        }

        /// <summary>
        /// Sets the current profile to a given one and returns an instance pointing
        /// to the previously set profile.
        /// </summary>
        /// <param name="newProfile">New memory manager profile</param>
        /// <exception cref="ArgumentNullException">if newProfile is null</exception>
        public static MMProf SwitchProfile(MMProf newProfile)
        {
            if (null == newProfile)
                throw new ArgumentNullException(nameof(newProfile));

            NativeMethods.MemoryManager_SwitchProfile(newProfile.NativePtr);

            MMProf oldProfile = profile_;
            profile_ = newProfile;

            return oldProfile;
        }

        /// <summary>
        /// Returns a MemoryPoolHandle according to the currently set memory manager
        /// profile and profOpt. The following values for profOpt have an effect
        /// independent of the current profile:
        ///
        ///     MMProfOpt.ForceNew: return MemoryPoolHandle.New()
        ///     MMProfOpt.ForceGlobal: return MemoryPoolHandle.Global()
        ///     MMProfOpt.ForceThreadLocal: return MemoryPoolHandle.ThreadLocal()
        ///
        /// Other values for profOpt are forwarded to the current profile and, depending
        /// on the profile, may or may not have an effect. The value MMProfOpt.Default
        /// will always invoke a default behavior for the current profile.
        /// </summary>
        /// <param name="profOpt">A MMProfOpt parameter used to provide additional
        /// instructions to the memory manager profile for internal logic.</param>
        /// <param name="clearOnDestruction">Indicates whether the memory pool data
        /// should be cleared when destroyed.This can be important when memory pools
        /// are used to store private data. This parameter is only used with MMProfOpt.ForceNew,
        /// and ignored in all other cases.</param>
        public static MemoryPoolHandle GetPool(MMProfOpt profOpt, bool clearOnDestruction = false)
        {
            NativeMethods.MemoryManager_GetPool((int)profOpt, clearOnDestruction, out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Returns a MemoryPoolHandle according to the currently set memory manager profile.
        /// </summary>
        public static MemoryPoolHandle GetPool()
        {
            NativeMethods.MemoryManager_GetPool(out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Currently set profile
        /// </summary>
        private static MMProf profile_ = null;
    }
}
