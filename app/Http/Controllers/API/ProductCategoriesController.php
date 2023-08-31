<?php

namespace App\Http\Controllers\API;

use App\Models\ProductCategories;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;

class ProductCategoriesController extends Controller
{
    public function all(Request $request){
        $id = $request->input('id');
        $limit = $request->input('limit', 6);
        $name = $request->input('name');
        $show_product = $request->input('show_product');

        if($id){
            $category = ProductCategories::with(['products'])->find($id);

            if($category)
            return ResponseFormatter::success($category, 'Data produk berhasil diambil');
            else return ResponseFormatter::error(null,'Data kategori produk tidak ada', 404);
        }

        $category = ProductCategories::query();
        if($name)$category->where('name','like','%' . $name . '%');

        if($show_product)
        $category->with('products');

        return ResponseFormatter::success($category->paginate($limit),'Data List Kategori Produk Berhasil Diambil');


    }
}
