<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Track;
use App\Models\Genre;
use App\Models\Album;
use App\Models\User;
use App\Support\SupabaseStorage;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;

class UploadController extends Controller
{
    /**
     * List genres
     */
    public function listGenres()
    {
        return Genre::all(['id', 'name']);
    }

    /**
     * List tracks
     */
    public function index()
    {
        $userId = Auth::id();
        $tracks = Track::with('user')->where('user_id', $userId)->latest()->get();

        // Map to include full URLs for audio and cover images
        $mapped = $tracks->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        });

        return response()->json($mapped->values()->all());
    }

    /**
     * Show a single track
     */
    public function show($id)
    {
        $track = Track::with('user')->findOrFail($id);
        $arr = $track->toArray();
        $arr['audio_url'] = SupabaseStorage::musicUrl($track->audio_file);
        $arr['cover_url'] = SupabaseStorage::imageUrl($track->cover_image);
        $arr['user'] = $track->user ? [
            'id' => $track->user->id,
            'username' => $track->user->username,
            'name' => $track->user->username, // Use username as name
        ] : null;
        $arr['username'] = $track->user?->username;
        return response()->json($arr);
    }

    /**
     * Update track metadata
     */
    public function update(Request $request, $id)
    {
        try {
            $track = Track::findOrFail($id);
            if ($track->user_id !== Auth::id()) {
                Log::warning('Unauthorized update attempt', ['track_id' => $id, 'user_id' => Auth::id()]);
                return response()->json(['message' => 'Forbidden'], 403);
            }

            Log::debug('UploadController.update request', [
                'id' => $id,
                'has_cover' => $request->hasFile('cover_image'),
                'content_length' => $request->header('content-length'),
                'content_type' => $request->header('content-type'),
                'authorization' => $request->header('authorization'),
                'all_input' => $request->except('cover_image'),
            ]);

            $request->merge(['album_id' => $request->input('album_id') === '' ? null : $request->input('album_id')] );
            $rules = [
                'album_id' => 'nullable|integer|exists:albums,id',
                'album' => 'nullable|string|max:255',
                'genre_id' => 'nullable|integer',
                'status' => 'nullable|string|max:255',
                'artist_name' => 'nullable|string|max:255',
            ];
            if ($request->has('title')) {
                $rules['title'] = 'required|string|max:255';
            } else {
                $rules['title'] = 'sometimes|string|max:255';
            }

            $request->validate($rules);

            if ($request->hasFile('cover_image')) {
                // store new cover
                $cover = $request->file('cover_image');
                $coverPath = $cover->store('covers', 'supabase_images');
                $track->cover_image = $coverPath;
            }

            if ($request->has('title')) {
                $track->title = $request->input('title');
            }
            if ($request->has('artist_name')) {
                $track->artist_name = $this->sanitizeArtistName($request->input('artist_name'));
            }

            if ($request->has('album_id')) {
                $track->album_id = $request->input('album_id');
                if ($request->input('album_id')) {
                    $album = Album::find($request->input('album_id'));
                    $track->album = $album ? $album->title : $request->input('album');
                } else {
                    $track->album = $request->input('album');
                }
            } elseif ($request->has('album')) {
                $track->album = $request->input('album');
            }

            if ($request->has('genre_id')) {
                $track->genre_id = $request->input('genre_id');
            }
            if ($request->has('status')) {
                $track->status = $request->input('status');
            }

            $track->save();

            $arr = $track->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($track->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($track->cover_image);

            Log::info('Track updated', ['track_id' => $track->id, 'user_id' => $track->user_id]);

            return response()->json($arr);
        } catch (\Exception $e) {
            Log::error('Error in UploadController.update', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return response()->json(['message' => 'Server error'], 500);
        }
    }

    /**
     * Delete a track
     */
    public function destroy($id)
    {
        $track = Track::findOrFail($id);
        if ($track->user_id !== Auth::id()) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        // delete files if present
        if ($track->audio_file) {
            Storage::disk('supabase_music')->delete($track->audio_file);
        }
        if ($track->cover_image) {
            Storage::disk('supabase_images')->delete($track->cover_image);
        }

        $track->delete();

        return response()->json(['success' => true]);
    }

    /**
     * Handle audio upload (audio-only)
     */
    public function upload(Request $request)
    {
        try {
            $genreId = $request->input('genre_id') ?? $request->input('genre');
            if ($genreId !== null) {
                $request->merge(['genre_id' => $genreId]);
            }

            Log::debug('UploadController.upload request', [
                'has_file' => $request->hasFile('file'),
                'content_length' => $request->header('content-length'),
                'content_type' => $request->header('content-type'),
                'authorization' => $request->header('authorization'),
                'genre' => $request->input('genre'),
                'genre_id' => $request->input('genre_id'),
                'artist_name' => $request->input('artist_name'),
                'all_input' => $request->except('file'),
            ]);

            Log::debug('UploadController.upload $_FILES', [
                'files' => $_FILES,
            ]);

            $request->merge(['album_id' => $request->input('album_id') === '' ? null : $request->input('album_id')] );
            $request->validate([
                'title' => 'required|string|max:255',
                'file' => 'required|file|mimes:mp3,wav,m4a,ogg,oga|max:102400',
                'cover_image' => 'nullable|image|max:10240',
                'album_id' => 'nullable|integer|exists:albums,id',
                'album' => 'nullable|string|max:255',
                'genre_id' => 'nullable|integer',
                'artist_name' => 'nullable|string|max:255',
            ]);

            if (!$request->hasFile('file')) {
                return response()->json([
                    'success' => false,
                    'message' => 'No file uploaded. Please select an audio file.',
                ], 422);
            }

            $file = $request->file('file');
            $path = $file->store('tracks', 'supabase_music');
            if (!$path) {
                Log::error('Audio file storage failed', [
                    'disk' => 'supabase_music',
                    'filename' => $file->getClientOriginalName(),
                    'size' => $file->getSize(),
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Audio upload failed. Check the Supabase music bucket configuration.',
                ], 500);
            }

            // store cover image if provided
            $coverPath = null;
            if ($request->hasFile('cover_image')) {
                $cover = $request->file('cover_image');
                $coverPath = $cover->store('covers', 'supabase_images');
                if (!$coverPath) {
                    Storage::disk('supabase_music')->delete($path);
                    Log::error('Track cover image storage failed', [
                        'disk' => 'supabase_images',
                        'filename' => $cover->getClientOriginalName(),
                        'size' => $cover->getSize(),
                    ]);

                    return response()->json([
                        'success' => false,
                        'message' => 'Cover upload failed. Please try a different image.',
                    ], 500);
                }
            }

            $artist = $this->sanitizeArtistName($request->input('artist_name'));
            $albumId = $request->input('album_id');
            $albumTitle = null;
            if ($albumId) {
                $album = Album::find($albumId);
                $albumTitle = $album ? $album->title : $request->input('album');
            }

            Log::info('Audio file stored', [
                'disk' => 'supabase_music',
                'path' => $path,
                'user_id' => $request->user()?->id,
            ]);

            try {
                $track = DB::transaction(function () use ($request, $artist, $albumId, $albumTitle, $path, $coverPath) {
                    return Track::create([
                        'title' => $request->input('title'),
                        'user_id' => $request->user()?->id,
                        'artist_name' => $artist,
                        'album_id' => $albumId,
                        'album' => $albumTitle ?? $request->input('album'),
                        'genre_id' => $request->input('genre_id'),
                        'audio_file' => $path,
                        'cover_image' => $coverPath,
                        'status' => 'published',
                    ]);
                });
            } catch (\Throwable $e) {
                Storage::disk('supabase_music')->delete($path);
                if ($coverPath) {
                    Storage::disk('supabase_images')->delete($coverPath);
                }

                Log::error('Track database insert failed after file upload', [
                    'message' => $e->getMessage(),
                    'audio_path' => $path,
                    'cover_path' => $coverPath,
                    'user_id' => $request->user()?->id,
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Audio was uploaded, but the track could not be saved to the database.',
                ], 500);
            }

            Log::info('Track uploaded', [
                'track_id' => $track->id,
                'user_id' => $track->user_id,
                'audio_file' => $track->audio_file,
                'cover_image' => $track->cover_image,
            ]);

            return response()->json([
                'success' => true,
                'track' => $track,
                'audio_file' => $path,
                'url' => SupabaseStorage::musicUrl($path),
            ], 201);
        } catch (\Illuminate\Validation\ValidationException $e) {
            throw $e;
        } catch (\Throwable $e) {
            Log::error('Error in UploadController.upload', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Track upload failed. Please try again.',
            ], 500);
        }
    }

    /**
     * Get random tracks for radio (shuffled)
     */
    public function radio()
    {
        $limit = request('limit', 20);
        $tracks = Track::with('user')
            ->where('status', 'published')
            ->inRandomOrder()
            ->limit($limit)
            ->get();

        $mapped = $tracks->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        });

        return response()->json($mapped->values()->all());
    }

    /**
     * Get new released tracks
     */
    public function newReleases()
    {
        $limit = request('limit', 10);
        $tracks = Track::with('user')
            ->where('status', 'published')
            ->latest('created_at')
            ->limit($limit)
            ->get();

        $mapped = $tracks->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        });

        return response()->json($mapped->values()->all());
    }

    public function publicTracks(Request $request)
    {
        $limit = $request->query('limit', 20);
        $offset = $request->query('offset', 0);

        $query = Track::with('user')
            ->where('status', 'published')
            ->latest('created_at');

        $tracks = $query->offset($offset)->limit($limit)->get();

        $mapped = $tracks->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        });

        return response()->json($mapped->values()->all());
    }

    /**
     * Search across tracks, albums and users.
     */
    public function search(Request $request)
    {
        // accept either `q` or `query` from clients
        $q = trim($request->query('q', $request->query('query', '')));
        $limit = (int) $request->query('limit', 20);
        $offset = (int) $request->query('offset', 0);

        if ($q === '') {
            return response()->json(['tracks' => [], 'albums' => [], 'artists' => []]);
        }

        // tracks: only published
        $tracksQuery = Track::with('user')
            ->where('status', 'published')
            ->where(function ($w) use ($q) {
                $w->where('title', 'like', "%{$q}%")
                  ->orWhere('artist_name', 'like', "%{$q}%")
                  ->orWhere('album', 'like', "%{$q}%")
                  ->orWhereHas('user', function ($userQuery) use ($q) {
                      $userQuery->where('username', 'like', "%{$q}%");
                  });
            })
            ->latest('created_at')
            ->offset($offset)
            ->limit($limit);

        $tracks = $tracksQuery->get()->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        })->values()->all();

        // albums: only published
        $albums = Album::with('user')
            ->where('status', 'published')
            ->where(function ($w) use ($q) {
                $w->where('title', 'like', "%{$q}%")
                  ->orWhere('artist_name', 'like', "%{$q}%");
            })
            ->latest('created_at')
            ->offset($offset)
            ->limit($limit)
            ->get()
            ->map(function ($album) {
                $data = $album->toArray();
                $data['cover_url'] = SupabaseStorage::imageUrl($album->cover_image);
                $data['user'] = $album->user ? [
                    'id' => $album->user->id,
                    'username' => $album->user->username,
                    'name' => $album->user->username, // Use username as name
                ] : null;
                $data['username'] = $album->user?->username;
                return $data;
            })->values()->all();

        // artists (users) - keep key name as `artists` for frontend compatibility
        $artists = User::where(function ($w) use ($q) {
                $w->where('username', 'like', "%{$q}%");
            })
            ->latest('created_at')
            ->offset($offset)
            ->limit($limit)
            ->get()
            ->map(function ($user) {
                $u = $user->toArray();
                $u['name'] = $user->username; // Added for frontend compatibility
                $u['profile_image_url'] = SupabaseStorage::imageUrl($user->profile_image);
                return $u;
            })->values()->all();

        return response()->json([
            'tracks' => $tracks,
            'albums' => $albums,
            'artists' => $artists,
        ]);
    }

    /**
     * Show public user profile (with tracks and albums).
     */
    public function showUser($id)
    {
        $user = User::findOrFail($id);

        $viewerId = Auth::id();
        $limit = (int) request('limit', 20);
        $offset = (int) request('offset', 0);

        $tracksQuery = Track::with('user')->where('user_id', $id);
        if ($viewerId !== $user->id) {
            $tracksQuery->where('status', 'published');
        }
        $tracks = $tracksQuery
            ->latest('created_at')
            ->offset($offset)
            ->limit($limit)
            ->get()
            ->map(function (Track $t) {
                $arr = $t->toArray();
                $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
                $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
                $arr['username'] = $t->user?->username;
                return $arr;
            })->values()->all();

        $albumsQuery = Album::with('user')->where('user_id', $id);
        if ($viewerId !== $user->id) {
            $albumsQuery->where('status', 'published');
        }
        $albums = $albumsQuery->latest('created_at')->get()->map(function ($album) {
            $data = $album->toArray();
            $data['cover_url'] = SupabaseStorage::imageUrl($album->cover_image);
            return $data;
        })->values()->all();

        $data = $user->toArray();
        $data['name'] = $user->username;
        $data['profile_image_url'] = SupabaseStorage::imageUrl($user->profile_image);
        $data['tracks'] = $tracks;
        $data['albums'] = $albums;

        return response()->json($data);
    }

    public function genreTracks($genreId)
    {
        $limit = request('limit', 10);
        $offset = request('offset', 0);
        $random = filter_var(request('random', false), FILTER_VALIDATE_BOOLEAN);

        $query = Track::with('user')
            ->where('genre_id', $genreId)
            ->where('status', 'published');

        if ($random) {
            $query->inRandomOrder();
        } else {
            $query->latest('created_at');
        }

        $tracks = $query->offset($offset)->limit($limit)->get();

        $mapped = $tracks->map(function (Track $t) {
            $arr = $t->toArray();
            $arr['audio_url'] = SupabaseStorage::musicUrl($t->audio_file);
            $arr['cover_url'] = SupabaseStorage::imageUrl($t->cover_image);
            $arr['user'] = $t->user ? [
                'id' => $t->user->id,
                'username' => $t->user->username,
                'name' => $t->user->username, // Use username as name
            ] : null;
            $arr['username'] = $t->user?->username;
            return $arr;
        });

        return response()->json($mapped->values()->all());
    }

    private function sanitizeArtistName($artistName)
    {
        if ($artistName === null) {
            return null;
        }

        $trimmed = trim($artistName);
        if ($trimmed === '') {
            return null;
        }

        if (strtolower($trimmed) === 'unknown artist') {
            return null;
        }

        return $trimmed;
    }
}
